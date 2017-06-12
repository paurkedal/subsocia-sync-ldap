(* subsocia-sync-ldap - Synchonizing LDAP to Subsocia
 * Copyright (C) 2017  University of Copenhagen
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

open Config
open Lwt.Infix
open Printf
open Subsocia_connection

module SASL = Netmech_krb5_sasl.Krb5_gs1 (Netgss.System)

let connect config =
  Lwt_log.ign_info_f "Connecting to %s." (Uri.to_string config.ldap_uri);
  let ldap_server, ldap_host =
    let uri = config.ldap_uri in
    (match Uri.scheme uri, Uri.host uri with
     | (Some "ldap" | None), Some host ->
        let port = match Uri.port uri with Some port -> port | None -> 389 in
        Netldap.ldap_server (`Inet_byname (host, port)), host
     | Some scheme, _ ->
        ksprintf failwith "Unsupported protocol %s." scheme
     | _, None ->
        failwith "Missing host name in LDAP uri.")
  in
  let ldap_conn = Netldap.connect ldap_server in
  Lwt_log.ign_info_f "Binding as %s." config.ldap_sasl_dn;
  let bind_creds =
    Netldap.sasl_bind_creds
      ~dn:config.ldap_sasl_dn
      ~user:config.ldap_sasl_user
      ~authz:""
      ~creds:[]
      ~params:["gssapi-acceptor", ("ldap@" ^ ldap_host), false]
      (module SASL)
  in
  Netldap.conn_bind ldap_conn bind_creds;
  ldap_conn

let process_entry config target = function
 | `Reference _ -> assert false
 | `Entry (dn, attrs) ->
    Lwt_log.info_f "Processing %s" dn

let process_target config ldap_conn (target_name, target) =
  let filter =
    `And [
      `Equality_match ("objectClass", "organizationalPerson");
    ]
  in
  let%lwt lr =
    Lwt_preemptive.detach
      (Netldap.search ldap_conn
        ~base:target.ldap_base_dn
        ~scope:`Sub
        ~deref_aliases:`Always
        ~size_limit:10 (* FIXME *)
        ~time_limit:10 (* FIXME *)
        ~types_only:false
        ~filter
        ~attributes:["cn"; "sn"; "givenName"; "mail"; "memberOf"])
      ()
  in
  (match lr#code with
   | `Success ->
      Lwt_list.iter_s (process_entry config target) lr#value
   | `TimeLimitExceeded ->
      Lwt_log.warning_f "Result is incomplete due to time limit." >>
      Lwt_list.iter_s (process_entry config target) lr#partial_value
   | `SizeLimitExceeded ->
      Lwt_log.warning_f "Result is incomplete due to size limit." >>
      Lwt_list.iter_s (process_entry config target) lr#partial_value
   | _ ->
      Lwt_log.error_f "LDAP search for target %s failed: %s"
        target_name lr#diag_msg)

let process config =
  let%lwt ldap_conn = Lwt_preemptive.detach connect config in
  Lwt_list.iter_s (process_target config ldap_conn)
                  (Dict.bindings config.targets) >>
  Lwt_log.info "Done."

let main config_file =
  let ini =
    try new Inifiles.inifile config_file with
     | Inifiles.Ini_parse_error (line, file) ->
        Printf.eprintf "%s:%d: Parse error.\n" file line;
        exit 65
  in
  let config = Config.of_inifile ini in
  process config

let main_cmd =
  let open Cmdliner in
  let config =
    Arg.(required @@ pos 0 (some file) None @@ info ~docv:"CONFIG" []) in
  let term = Term.(const main $ config) in
  let info = Term.info "subsocia-sync-ldap" in
  (term, info)

let () =
  (match Cmdliner.Term.eval main_cmd with
   | `Ok m -> Lwt_main.run m
   | `Error _ -> exit 64
   | `Help | `Version -> exit 0)
