(* subsocia-sync-ldap - Synchonizing LDAP to Subsocia
 * Copyright (C) 2017--2021  University of Copenhagen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *)

open Logging
open Lwt.Infix
open Lwt.Syntax

module Sasl_mech_krb5 = Netmech_krb5_sasl.Krb5_gs1 (Netgss.System)

type error = (string * Scope.error) list

let connect_ldap config =
  Logs.debug (fun m -> m "Connecting to %a." Uri.pp_hum config.Config.ldap_uri);
  let ldap_server, ldap_host =
    let uri = config.Config.ldap_uri in
    (match Uri.scheme uri, Uri.host uri with
     | (Some "ldap" | None), Some host ->
        let port = match Uri.port uri with Some port -> port | None -> 389 in
        let ssymb = `Inet_byname (host, port) in
        let timeout = config.Config.ldap_timeout in
        (Netldap.ldap_server ?timeout ssymb, host)
     | Some scheme, _ ->
        Fmt.failwith "Unsupported protocol %s." scheme
     | _, None ->
        failwith "Missing host name in LDAP uri.")
  in
  let ldap_conn = Netldap.connect ldap_server in
  let bind_creds =
    (match config.Config.ldap_bind with
     | Config.Ldap_bind_anon ->
        Logs.debug (fun m -> m "Binding anonymously.");
        Netldap.anon_bind_creds
     | Config.Ldap_bind_simple {dn; password = pw} ->
        Logs.debug (fun m -> m "Binding as %s." dn);
        Netldap.simple_bind_creds ~dn ~pw
     | Config.Ldap_bind_sasl_gssapi ->
        Logs.debug (fun m -> m "Binding with GSSAPI.");
        Netldap.sasl_bind_creds
          ~dn:""
          ~user:""
          ~authz:""
          ~creds:[]
          ~params:["gssapi-acceptor", ("ldap@" ^ ldap_host), false]
          (module Sasl_mech_krb5))
  in
  Netldap.conn_bind ldap_conn bind_creds;
  ldap_conn

let process config ~scopes ~period () =
  let* ldap_conn = Lwt_preemptive.detach connect_ldap config in
  let* csn_directory_state =
    (match config.Config.ldap_csn_state_cfg with
     | None -> Lwt.return_none
     | Some cfg ->
        let server_id = Uri.to_string config.Config.ldap_uri in
        Csn_state.Directory.load cfg server_id ldap_conn >|= Option.some)
  in
  let target_cache = Hashtbl.create 3 in
  let process_scope scope_name =
    let scope_cfg = Dict.find scope_name config.Config.scopes in
    let targets =
      let get_conn target_name =
        try Hashtbl.find target_cache target_name
        with Not_found ->
          let target_cfg = Dict.find target_name config.Config.targets in
          let conn = Target.connect config.template_env target_cfg in
          Hashtbl.add target_cache target_name conn;
          conn
      in
      List.map get_conn scope_cfg.Scope.Cfg.target_names
    in
    Scope.process
      ~commit:config.Config.commit ~period ~ldap_conn
      ~global_ldap_filters:config.Config.ldap_filters
      ~default_ldap_update_time_filter:config.Config.ldap_update_time_filter
      ~min_update_period:config.Config.min_update_period
      ~scope_name ~scope_cfg ~targets
      ?csn_directory_state
      () >|=
    (function
     | Ok () -> None
     | Error err -> Some (scope_name, err))
  in
  (match%lwt Lwt_list.filter_map_s process_scope scopes with
   | [] ->
      Log.debug (fun m -> m "Completed with no errors.") >>= fun () ->
      Lwt.return (Ok ())
   | scope_errors ->
      Log.err (fun m -> m "%d scopes failed." (List.length scope_errors))
        >>= fun () ->
      Lwt.return (Error scope_errors))
