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
open Printf
open Subsocia_common
open Unprime_list
open Unprime_option

module Dict = Config.Dict
module Sasl_mech_krb5 = Netmech_krb5_sasl.Krb5_gs1 (Netgss.System)
module String_set = Set.Make (String)

module Stats = struct
  type t = {
    mutable create_count: int;
    mutable update_count: int;
  }

  let create () = {create_count = 0; update_count = 0}

  let pp ppf stats =
    Format.fprintf ppf "%d created, %d updated"
      stats.create_count stats.update_count
end

let failwith_f fmt = ksprintf failwith fmt

let pp_ptimetz ppf (t, tz_offset_s) = Ptime.pp_human ~tz_offset_s () ppf t

let pp_period ppf = function
 | None, None -> Format.fprintf ppf "(-∞, ∞)"
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
        failwith_f "Unsupported protocol %s." scheme
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
          (module Sasl_mech_krb5)) in
  Netldap.conn_bind ldap_conn bind_creds;
  ldap_conn

let selector_of_string s =
  (try Subsocia_selector.selector_of_string s with
   | Invalid_argument _ -> failwith_f "Invalid selector %s." s)

(* Target Processing *)

module Make_target_conn (Sc : Subsocia_connection.S) = struct
  open Sc

  type attribute_binding =
   | Attribute_binding : 'a Attribute_type.t * 'a Values.t -> attribute_binding

  let create_entity target_path target_type =
    let pfx, aconj = Subsocia_selector.add_selector_of_selector target_path in
    let%lwt pfx_entity =
      (match pfx with
       | None -> Entity.get_root ()
       | Some pfx -> Entity.select_one pfx)
    in
    let resolve (atn, values) =
      let%lwt Attribute_type.Any at = Attribute_type.any_of_name_exn atn in
      let vt = Attribute_type.value_type at in
      let values = List.map (Value.typed_of_string vt) values in
      Lwt.return (Attribute_binding (at, Values.of_elements vt values))
    in
    let%lwt aconj = Lwt_list.map_s resolve (String_map.bindings aconj) in
    let%lwt entity = Entity.create target_type in
    Lwt_list.iter_s
      (fun (Attribute_binding (at, values)) ->
        Entity.set_values at values pfx_entity entity) aconj
    >|= fun () -> entity

  let process_attribution ~start_update config lentry target_entity attribution =
    let source_path_str =
      Variable.expand_single config ~lentry attribution.Config.source in
    let source_path = selector_of_string source_path_str in
    let%lwt source_entity = Entity.select_one source_path in
    let replace (atn, tmpl) =
      let%lwt Attribute_type.Any at = Attribute_type.any_of_name_exn atn in
      let vt = Attribute_type.value_type at in
      let values_str = Variable.expand_multi config ~lentry tmpl in
      let values = List.map (Value.typed_of_string vt) values_str in
      let values = Values.of_elements vt values in
      let%lwt old_values = Entity.get_values at source_entity target_entity in
      if Values.elements values = Values.elements old_values then
        Lwt.return_unit else
      Lazy.force start_update >>= fun () ->
      Commit_log.app (fun m ->
        m "- %s %s ↦ %s" atn
          (Values.to_json_string vt old_values)
          (Values.to_json_string vt values)) >>= fun () ->
      if not config.Config.commit then Lwt.return_unit else
      Entity.set_values at values source_entity target_entity
    in
    Lwt_list.iter_s replace attribution.Config.replace

  let select_or_warn sel =
    (match%lwt Entity.select_opt sel with
     | None ->
        Log.warn (fun m ->
          m "Cannot find %s."
            (Subsocia_selector.string_of_selector sel)) >>= fun () ->
        Lwt.return_none
     | Some ent ->
        Lwt.return_some ent)

  let process_inclusion ~start_update config lentry target_entity inclusion =
    let force_paths =
      Variable.expand_multi config ~lentry inclusion.Config.force_super in
    let force_paths = List.map selector_of_string force_paths in
    let%lwt force_entities = Lwt_list.filter_map_s select_or_warn force_paths in

    let force_super super_entity =
      if%lwt not =|< Entity.is_sub target_entity super_entity then begin
        let%lwt super_name = Entity.display_name super_entity in
        Lazy.force start_update >>= fun () ->
        Commit_log.app (fun m -> m "≼ %s" super_name) >>= fun () ->
        if not config.Config.commit then Lwt.return_unit else
        Entity.force_dsub target_entity super_entity
      end in

    let relax_super super_entity =
      if%lwt Entity.is_sub target_entity super_entity then begin
        let%lwt super_name = Entity.display_name super_entity in
        Lazy.force start_update >>= fun () ->
        Commit_log.app (fun m -> m "⋠ %s" super_name) >>= fun () ->
        if not config.Config.commit then Lwt.return_unit else
        Entity.relax_dsub target_entity super_entity
      end in

    Lwt_list.iter_s force_super force_entities >>= fun () ->
    (match inclusion.Config.relax_super with
     | None -> Lwt.return_unit
     | Some relax_paths ->
        let relax_paths = Variable.expand_multi config ~lentry relax_paths in
        let relax_paths = List.map selector_of_string relax_paths in
        let%lwt relax_entities = Lwt_list.map_s Entity.select relax_paths in
        let relax_entities = Entity.Set.empty
          |> List.fold Entity.Set.union relax_entities
          |> List.fold Entity.Set.remove force_entities in
        Entity.Set.iter_s relax_super relax_entities)

  let update_entity ?(start_update = lazy Lwt.return_unit)
                    config lentry target target_entity =
    Lwt_list.iter_s
      (process_attribution ~start_update config lentry target_entity)
      target.Config.attributions >>= fun () ->
    Lwt_list.iter_s
      (process_inclusion ~start_update config lentry target_entity)
      target.Config.inclusions

  let check_create_condition config lentry target =
    (match target.Config.create_if_exists with
     | None -> true
     | Some tmpl -> Variable.expand_multi config ~lentry tmpl != [])

  let process_entry config stats target target_type = function
   | `Reference _ -> assert false
   | `Entry ((dn, _) as lentry) ->
      let target_path_str =
        Variable.expand_single config ~lentry target.Config.entity_path in
      let target_path = selector_of_string target_path_str in
      Log.debug (fun m -> m "Processing %s => %s" dn target_path_str)
        >>= fun () ->
      (match%lwt Entity.select_opt target_path with
       | None ->
          if check_create_condition config lentry target then begin
            Stats.(stats.create_count <- stats.create_count + 1);
            Commit_log.app (fun m -> m "N %s ↦ %s" dn target_path_str)
              >>= fun () ->
            if not config.Config.commit then Lwt.return_unit else
            create_entity target_path target_type >>=
            update_entity config lentry target
          end else Lwt.return_unit
       | Some target_entity ->
          let start_update = lazy begin
            Stats.(stats.update_count <- stats.update_count + 1);
            Commit_log.app (fun m -> m "U %s ↦ %s" dn target_path_str)
          end in
          update_entity ~start_update config lentry target target_entity)

  let process config stats target lr lr_value =
    let%lwt target_type = Entity_type.of_name_exn target.Config.entity_type in
    Lwt_list.iter_s (process_entry config stats target target_type) lr_value
      >>= fun () ->
    Log.info (fun m -> m
      "Processed %d LDAP entries, %a." (List.length lr#value) Stats.pp stats)
end

let format_ptime fmt (t, tz_offset_s) tz_offset_s_cfg =
  let tz_offset_s_out =
    (match tz_offset_s_cfg with
     | None -> tz_offset_s
     | Some tz_offset_s -> tz_offset_s) in
  let (tY, tM, tD), ((tH, tN, tS), tz_offset_s) = Ptime.to_date_time t in
  assert (tz_offset_s = 0);
  assert (tz_offset_s_out mod 3600 = 0);
  let open CalendarLib in
  let tz = Time_Zone.UTC_Plus (tz_offset_s_out / 3600) in
  Time_Zone.on
    (Printer.Calendar.sprint fmt) tz
    (Calendar.make tY tM tD tH tN tS)

let rec process_scope config period ldap_conn subsocia_conn_cache scope_name =
  let retry_period period =
    process_scope config period ldap_conn subsocia_conn_cache scope_name in
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
     | None -> config.Config.ldap_update_time_filter) in
  let filter =
    (match period, ldap_update_time_filter with
     | (None, None), None -> filter
     | (_, _), None ->
        failwith_f "No update time filter provided for scope %s" scope_name
     | (tI, tF), Some (fitI, fitF, fmt, tz) ->
        let mk_time_filter fit t =
          let t_str = format_ptime fmt t tz in
          Netldapx.Filter_template.expand
            (function "t" -> t_str | x -> failwith_f "Undefined variable %s." x)
            fit
        in
        let subfilters =
          [filter]
            |> Option.fold (List.cons % mk_time_filter fitI) tI
            |> Option.fold (List.cons % mk_time_filter fitF) tF in
        `And subfilters)
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
    List.map (fun target_name -> Dict.find target_name config.Config.targets)
    scope.Config.target_names in
  let%lwt lr =
    let target_attributes target =
      String_set.empty |> List.fold String_set.add target.Config.ldap_attributes
    in
    let attributes =
      List.fold (String_set.union % target_attributes) targets String_set.empty
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
  let stats = Stats.create () in
  let process_targets lr_value =
    targets |> Lwt_list.iter_p begin fun target ->
      let subsocia_conn =
        let uri = Variable.expand_single config target.Config.subsocia_uri in
        try Hashtbl.find subsocia_conn_cache uri
        with Not_found ->
          let conn = Subsocia_connection.connect (Uri.of_string uri) in
          Hashtbl.add subsocia_conn_cache uri conn; conn
      in
      let module Subsocia_conn = (val subsocia_conn) in
      let module Target_conn = Make_target_conn (Subsocia_conn) in
      Target_conn.process config stats target lr lr_value
    end
  in
  (match lr#code with
   | `Success ->
      process_targets lr#value >>= fun () ->
      Lwt.return_none
   | `TimeLimitExceeded ->
      Log.err (fun m ->
        m "Result for %s is incomplete due to time limit."
          scope_name) >>= fun () ->
      begin
        if not scope.Config.partial_is_ok then Lwt.return_unit else
        process_targets lr#partial_value
      end >>= fun () ->
      Lwt.return_some (scope_name, `Time_limit_exceeded)
   | `SizeLimitExceeded ->
      (match period with
       | (Some (tI, tzI) as tI'), (Some (tF, _) as tF') when
            Ptime.Span.compare (Ptime.diff tF tI)
                               config.Config.min_update_period > 0 ->
          Log.warn (fun m -> m
            "Size limit exceeded for period %a, splitting period."
            pp_period period)
            >>= fun () ->
          let dtIM = Option.get @@ Ptime.Span.of_float_s @@
            0.5 *. Ptime.Span.to_float_s (Ptime.diff tF tI) in
          let tM' = Some (Ptime.add_span tI dtIM |> Option.get, tzI) in
          (match%lwt retry_period (tI', tM') with
           | None -> retry_period (tM', tF')
           | Some err -> Lwt.return_some err)
       | _ ->
          Log.err (fun m ->
            m "Result for %s is incomplete due to size limit." scope_name)
            >>= fun () ->
          begin
            if not scope.Config.partial_is_ok then Lwt.return_unit else
            process_targets lr#partial_value
          end >>= fun () ->
          Lwt.return_some (scope_name, `Size_limit_exceeded))
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
  let%lwt ldap_conn = Lwt_preemptive.detach connect config in
  let subsocia_conn_cache = Hashtbl.create 3 in
  (match%lwt
    Lwt_list.filter_map_s
      (process_scope config period ldap_conn subsocia_conn_cache)
      scopes
   with
   | [] ->
      Log.debug (fun m -> m "Completed with no errors.") >>= fun () ->
      Lwt.return (Ok ())
   | scope_errors ->
      Log.err (fun m -> m "%d scopes failed." (List.length scope_errors))
        >>= fun () ->
      Lwt.return (Error scope_errors))
