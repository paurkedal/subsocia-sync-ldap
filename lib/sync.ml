(* subsocia-sync-ldap - LDAP to Subsocia Synchronization
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

open Logging
open Lwt.Infix
open Lwt.Syntax
open Unprime_list
open Unprime_option

module Dict = Config.Dict
module Sasl_mech_krb5 = Netmech_krb5_sasl.Krb5_gs1 (Netgss.System)
module String_set = Set.Make (String)

let pp_ptimetz ppf (t, tz_offset_s) = Ptime.pp_human ~tz_offset_s () ppf t

let pp_period ppf = function
 | None, None -> Format.pp_print_string ppf "(-∞, ∞)"
 | None, Some tF -> Format.fprintf ppf "(-∞, %a)" pp_ptimetz tF
 | Some tI, None -> Format.fprintf ppf "[%a, ∞)" pp_ptimetz tI
 | Some tI, Some tF -> Format.fprintf ppf "[%a, %a)" pp_ptimetz tI pp_ptimetz tF

let connect config =
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

let format_ptime fmt (t, tz_offset_s) tz_offset_s_cfg =
  let zone =
    let tz_s =
      (match tz_offset_s_cfg with
       | None -> tz_offset_s
       | Some tz_offset_s -> tz_offset_s)
    in
    if tz_s mod 60 = 0 then tz_s / 60 else
    failwith "Cannot format time using sub-minute time zone."
  in
  Netdate.create ~zone (Ptime.to_float_s t) |> Netdate.format ~fmt

let rec process_scope
    ~config ~period ?partition_lb ?partition_ub ~ldap_conn ~target_cache
    scope_name =
  let retry_period period =
    process_scope
      ~config ~period ?partition_lb ?partition_ub
      ~ldap_conn ~target_cache scope_name
  in
  let retry_partition partition_lb partition_ub =
    process_scope
      ~config ~period ?partition_lb ?partition_ub
      ~ldap_conn ~target_cache scope_name
  in
  let scope = Dict.find scope_name config.Config.scopes in

  (* Combine global and scope filters *)
  let filter =
    (match config.Config.ldap_filters, scope.Config.ldap_filters with
     | [], [] -> failwith "No LDAP filter provided."
     | [], sfilters -> `And sfilters
     | cfilters, [] -> `And cfilters
     | cfilters, tfilters -> `And (tfilters @ cfilters))
  in

  (* Add update time filters *)
  let ldap_update_time_filter =
    (match scope.Config.ldap_update_time_filter with
     | Some _ as fit -> fit
     | None -> config.Config.ldap_update_time_filter)
  in
  let filter =
    (match period, ldap_update_time_filter with
     | (None, None), None -> filter
     | (_, _), None ->
        Fmt.failwith "No update time filter provided for scope %s" scope_name
     | (tI, tF), Some (fitI, fitF, fmt, tz) ->
        let mk_time_filter fit t =
          let t_str = format_ptime fmt t tz in
          Netldapx.Filter_template.expand
            (function
             | "t" -> t_str
             | x -> Fmt.failwith "Undefined variable %s." x)
            fit
        in
        let subfilters =
          [filter]
            |> Option.fold (List.cons % mk_time_filter fitI) tI
            |> Option.fold (List.cons % mk_time_filter fitF) tF
        in
        `And subfilters)
  in
  let filter =
    (match scope.Config.ldap_partition_attribute_type with
     | None -> filter
     | Some attr_type ->
        let ge v = `Greater_or_equal (attr_type, v) in
        (match partition_lb, partition_ub with
         | None, None -> filter
         | Some lb, None -> `And [filter; ge lb]
         | None, Some ub -> `And [filter; `Not (ge ub)]
         | Some lb, Some ub -> `And [filter; ge lb; `Not (ge ub)]))
  in

  Log.info (fun m -> m "Scope %s %a:" scope_name pp_period period)
    >>= fun () ->
  Log.debug (fun m -> m "LDAP base: %s" scope.Config.ldap_base_dn)
    >>= fun () ->
  Log.debug (fun m -> m "LDAP scope: %s"
                            (Netldapx.string_of_scope scope.Config.ldap_scope))
    >>= fun () ->
  Log.debug (fun m -> m "LDAP filter: %s" (Netldapx.string_of_filter filter))
    >>= fun () ->

  let targets =
    let get_conn target_name =
      try Hashtbl.find target_cache target_name
      with Not_found ->
        let conn = Target.connect config target_name in
        Hashtbl.add target_cache target_name conn;
        conn
    in
    List.map get_conn scope.Config.target_names
  in

  let* lr =
    let attributes =
      String_set.empty
        |> List.fold (List.fold String_set.add % Target.ldap_attributes) targets
    in
    Lwt_preemptive.detach
      (Netldap.search ldap_conn
        ~base:scope.Config.ldap_base_dn
        ~scope:scope.Config.ldap_scope
        ~deref_aliases:`Always
        ~size_limit:(Option.get_or 0 scope.Config.ldap_size_limit)
        ~time_limit:(Option.get_or 0 scope.Config.ldap_time_limit)
        ~types_only:false
        ~filter
        ~attributes:(String_set.elements attributes))
      ()
  in
  let process_targets entries =
    Lwt_list.iter_p (fun target -> Target.process target entries) targets
  in
  (match lr#code with
   | `Success ->
      process_targets lr#value >>= fun () ->
      Lwt.return_none
   | `TimeLimitExceeded ->
      Log.err (fun m ->
        m "Result for %s is incomplete due to time limit."
          scope_name) >>= fun () ->
      let+ () =
        if not scope.Config.partial_is_ok then Lwt.return_unit else
        process_targets lr#partial_value
      in
      Some (scope_name, `Time_limit_exceeded)
   | `SizeLimitExceeded ->
      (match period, scope.Config.ldap_partition_attribute_type with
       | ((Some (tI, tzI) as tI'), (Some (tF, _) as tF')), _ when
            Ptime.Span.compare (Ptime.diff tF tI)
                               config.Config.min_update_period > 0 ->
          Log.warn (fun f ->
            f "Size limit exceeded for period %a, splitting period."
              pp_period period) >>= fun () ->
          let dtIM = Option.get @@ Ptime.Span.of_float_s @@
            0.5 *. Ptime.Span.to_float_s (Ptime.diff tF tI) in
          let tM' = Some (Ptime.add_span tI dtIM |> Option.get, tzI) in
          (match%lwt retry_period (tI', tM') with
           | None -> retry_period (tM', tF')
           | Some err -> Lwt.return_some err)
       | _, Some attr_type ->
          let entries = lr#partial_value in
          (match List.nth entries (Random.int (List.length entries)) with
           | `Entry (_, attrs) ->
              (match List.assoc_opt attr_type attrs with
               | Some (partition :: _) ->
                  Log.warn (fun f ->
                    f "Size limit exceeded for period %a, splitting on %s=%s."
                      pp_period period attr_type partition) >>= fun () ->
                  (match%lwt retry_partition partition_lb (Some partition) with
                   | None -> retry_partition (Some partition) partition_ub
                   | Some err -> Lwt.return_some err)
               | Some [] | None ->
                  Log.err (fun f ->
                    f "Size limit exceeded and no attribute value to split on.")
                    >|= fun () ->
                  Some (scope_name, `Size_limit_exceeded))
           | `Reference _ -> assert false)
       | _ ->
          Log.err (fun m ->
            m "Result for %s is incomplete due to size limit." scope_name)
            >>= fun () ->
          let+ () =
            if not scope.Config.partial_is_ok then Lwt.return_unit else
            process_targets lr#partial_value
          in
          Some (scope_name, `Size_limit_exceeded))
   | _ ->
      Log.err (fun m ->
        m "LDAP search for scope %s failed: %s" scope_name lr#diag_msg)
        >>= fun () ->
      Lwt.return_some (scope_name, `Search_failed))

type scope_error =
 [ `Search_failed
 | `Time_limit_exceeded
 | `Size_limit_exceeded ]

type error = (string * scope_error) list

type time = Ptime.t * Ptime.tz_offset_s

let process config ~scopes ~period () =
  let* ldap_conn = Lwt_preemptive.detach connect config in
  let target_cache = Hashtbl.create 3 in
  (match%lwt
    Lwt_list.filter_map_s
      (process_scope ~config ~period ~ldap_conn ~target_cache)
      scopes
   with
   | [] ->
      Log.debug (fun m -> m "Completed with no errors.") >>= fun () ->
      Lwt.return (Ok ())
   | scope_errors ->
      Log.err (fun m -> m "%d scopes failed." (List.length scope_errors))
        >>= fun () ->
      Lwt.return (Error scope_errors))
