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

open Lwt.Infix
open Printf
open Subsocia_common
open Subsocia_connection
open Unprime_list
open Unprime_option

module Dict = Config.Dict
module Sasl_mech_krb5 = Netmech_krb5_sasl.Krb5_gs1 (Netgss.System)

let failwith_f fmt = ksprintf failwith fmt

let connect config =
  Lwt_log.ign_info_f "Connecting to %s." (Uri.to_string config.Config.ldap_uri);
  let ldap_server, ldap_host =
    let uri = config.Config.ldap_uri in
    (match Uri.scheme uri, Uri.host uri with
     | (Some "ldap" | None), Some host ->
        let port = match Uri.port uri with Some port -> port | None -> 389 in
        Netldap.ldap_server (`Inet_byname (host, port)), host
     | Some scheme, _ ->
        failwith_f "Unsupported protocol %s." scheme
     | _, None ->
        failwith "Missing host name in LDAP uri.")
  in
  let ldap_conn = Netldap.connect ldap_server in

  let bind_creds =
    (match config.Config.ldap_bind with
     | Config.Ldap_bind_anon ->
        Lwt_log.ign_info "Binding anonymously.";
        Netldap.anon_bind_creds
     | Config.Ldap_bind_simple {dn; password = pw} ->
        Lwt_log.ign_info_f "Binding as %s." dn;
        Netldap.simple_bind_creds ~dn ~pw
     | Config.Ldap_bind_sasl_gssapi ->
        Lwt_log.ign_info "Binding with GSSAPI.";
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

type attribute_binding =
 | Attribute_binding : 'a Attribute_type.t * 'a Values.t -> attribute_binding

let create_entity target_path target_type =
  let pfx, aconj = Subsocia_selector.add_selector_of_selector target_path in
  let%lwt pfx_entity =
    (match pfx with
     | None -> Entity.root
     | Some pfx -> Entity.select_one pfx)
  in
  let resolve (atn, values) =
    let%lwt Attribute_type.Ex at = Attribute_type.required atn in
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

let process_attribution ~log_header config lentry target_entity attribution =
  let source_path_str =
    Variable.expand_single config ~lentry attribution.Config.source in
  let source_path = selector_of_string source_path_str in
  let%lwt source_entity = Entity.select_one source_path in
  let replace (atn, tmpl) =
    Lwt_log.debug_f "R %s" atn >>
    let%lwt Attribute_type.Ex at = Attribute_type.required atn in
    let vt = Attribute_type.value_type at in
    let values_str = Variable.expand_multi config ~lentry tmpl in
    let values = List.map (Value.typed_of_string vt) values_str in
    let values = Values.of_elements vt values in
    let%lwt old_values = Entity.get_values at source_entity target_entity in
    if Values.elements values = Values.elements old_values then
      Lwt.return_unit else
    Lazy.force log_header >>
    Lwt_log.info_f "- %s %s ↦ %s" atn
      (Values.to_json_string vt old_values)
      (Values.to_json_string vt values) >>
    if not config.Config.commit then Lwt.return_unit else
    Entity.set_values at values source_entity target_entity
  in
  Lwt_list.iter_s replace attribution.Config.replace

let select_or_warn sel =
  (match%lwt Entity.select_opt sel with
   | None ->
      Lwt_log.warning_f "Cannot find %s."
        (Subsocia_selector.string_of_selector sel) >>
      Lwt.return_none
   | Some ent ->
      Lwt.return_some ent)

let process_inclusion ~log_header config lentry target_entity inclusion =
  let force_paths =
    Variable.expand_multi config ~lentry inclusion.Config.force_super in
  let force_paths = List.map selector_of_string force_paths in
  let%lwt force_entities = Lwt_list.filter_map_s select_or_warn force_paths in

  let force_super super_entity =
    if%lwt not =|< Entity.is_sub target_entity super_entity then begin
      let%lwt super_name = Entity.display_name super_entity in
      Lazy.force log_header >>
      Lwt_log.info_f "≼ %s" super_name >>
      if not config.Config.commit then Lwt.return_unit else
      Entity.force_dsub target_entity super_entity
    end in

  let relax_super super_entity =
    if%lwt Entity.is_sub target_entity super_entity then begin
      let%lwt super_name = Entity.display_name super_entity in
      Lazy.force log_header >>
      Lwt_log.info_f "⋠ %s" super_name >>
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

let update_entity ?(log_header = lazy Lwt.return_unit)
                  config lentry target target_entity =
  Lwt_list.iter_s (process_attribution ~log_header config lentry target_entity)
    target.Config.attributions >>
  Lwt_list.iter_s (process_inclusion ~log_header config lentry target_entity)
    target.Config.inclusions

let process_entry config target target_type = function
 | `Reference _ -> assert false
 | `Entry ((dn, _) as lentry) ->
    let target_path_str =
      Variable.expand_single config ~lentry target.Config.entity_path in
    let target_path = selector_of_string target_path_str in
    Lwt_log.debug_f "Processing %s => %s" dn target_path_str >>
    (match%lwt Entity.select_opt target_path with
     | None ->
        Lwt_log.info_f "N %s ↦ %s" dn target_path_str >>
        if not config.Config.commit then Lwt.return_unit else
        create_entity target_path target_type >>=
        update_entity config lentry target
     | Some target_entity ->
        let log_header = lazy (Lwt_log.info_f "U %s ↦ %s" dn target_path_str) in
        update_entity ~log_header config lentry target target_entity)

let process_scope config ldap_conn scope_name =
  let scope = Dict.find scope_name config.Config.scopes in
  let target = Dict.find scope.Config.target_name config.Config.targets in
  let filter =
    (match config.Config.ldap_filters, scope.Config.ldap_filters with
     | [], [] -> failwith "No LDAP filter provided."
     | [], sfilters -> `And sfilters
     | cfilters, [] -> `And cfilters
     | cfilters, tfilters -> `And (tfilters @ cfilters))
  in
  Lwt_log.info_f "LDAP base: %s" scope.Config.ldap_base_dn >>
  Lwt_log.info_f "LDAP scope: %s"
                 (Netldapx.string_of_scope scope.Config.ldap_scope)>>
  Lwt_log.info_f "LDAP filter: %s" (Netldapx.string_of_filter filter) >>
  let%lwt target_type = Entity_type.required target.Config.entity_type in
  let%lwt lr =
    Lwt_preemptive.detach
      (Netldap.search ldap_conn
        ~base:scope.Config.ldap_base_dn
        ~scope:scope.Config.ldap_scope
        ~deref_aliases:`Always
        ~size_limit:(Option.get_or 0 scope.Config.ldap_size_limit)
        ~time_limit:(Option.get_or 0 scope.Config.ldap_time_limit)
        ~types_only:false
        ~filter
        ~attributes:target.Config.ldap_attributes)
      ()
  in
  (match lr#code with
   | `Success ->
      Lwt_list.iter_s (process_entry config target target_type) lr#value >>
      Lwt.return_none
   | `TimeLimitExceeded ->
      Lwt_log.error_f "Result for %s is incomplete due to time limit."
                      scope_name >>= fun () ->
      begin
        if not scope.Config.partial_is_ok then Lwt.return_unit else
        Lwt_list.iter_s (process_entry config target target_type)
                        lr#partial_value
      end >>
      Lwt.return_some (scope_name, `Time_limit_exceeded)
   | `SizeLimitExceeded ->
      Lwt_log.error_f "Result for %s is incomplete due to size limit."
                      scope_name >>= fun () ->
      begin
        if not scope.Config.partial_is_ok then Lwt.return_unit else
        Lwt_list.iter_s (process_entry config target target_type)
                        lr#partial_value
      end >>
      Lwt.return_some (scope_name, `Size_limit_exceeded)
   | _ ->
      Lwt_log.error_f "LDAP search for scope %s failed: %s"
                      scope_name lr#diag_msg >>
      Lwt.return_some (scope_name, `Search_failed))

type scope_error =
 [ `Search_failed
 | `Time_limit_exceeded
 | `Size_limit_exceeded ]

type error = (string * scope_error) list

let process config ~scopes =
  let%lwt ldap_conn = Lwt_preemptive.detach connect config in
  (match%lwt Lwt_list.filter_map_s (process_scope config ldap_conn) scopes with
   | [] ->
      Lwt_log.info "Completed with no errors." >>
      Lwt.return (Ok ())
   | scope_errors ->
      Lwt_log.error_f "%d scopes failed." (List.length scope_errors) >>
      Lwt.return (Error scope_errors))
