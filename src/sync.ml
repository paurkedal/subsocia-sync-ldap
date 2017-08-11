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

open Config
open Lwt.Infix
open Printf
open Subsocia_common
open Subsocia_connection
open Unprime_list
open Unprime_option

module SASL = Netmech_krb5_sasl.Krb5_gs1 (Netgss.System)

let failwith_f fmt = ksprintf failwith fmt

let connect config =
  Lwt_log.ign_info_f "Connecting to %s." (Uri.to_string config.ldap_uri);
  let ldap_server, ldap_host =
    let uri = config.ldap_uri in
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

let process_attribution config lentry target_entity attribution =
  let source_path_str =
    Variable.expand_single config ~lentry attribution.source in
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
    Lwt_log.info_f "- %s %s ↦ %s" atn
      (Values.to_json_string vt old_values)
      (Values.to_json_string vt values) >>
    if not config.commit then Lwt.return_unit else
    Entity.set_values at values source_entity target_entity
  in
  Lwt_list.iter_s replace attribution.replace

let select_or_warn sel =
  (match%lwt Entity.select_opt sel with
   | None ->
      Lwt_log.warning_f "Cannot find %s."
        (Subsocia_selector.string_of_selector sel) >>
      Lwt.return_none
   | Some ent ->
      Lwt.return_some ent)

let process_inclusion config lentry target_entity inclusion =
  (* TODO: inclusion.relax_super *)
  let fsup_paths = Variable.expand_multi config ~lentry inclusion.force_super in
  let fsup_paths = List.map selector_of_string fsup_paths in
  let%lwt fsup_entities = Lwt_list.filter_map_s select_or_warn fsup_paths in
  let force_super super_entity =
    if%lwt not =|< Entity.is_sub target_entity super_entity then begin
      let%lwt super_name = Entity.display_name super_entity in
      Lwt_log.info_f "≼ %s" super_name >>
      if not config.commit then Lwt.return_unit else
      Entity.force_dsub target_entity super_entity
    end
  in
  Lwt_list.iter_s force_super fsup_entities

let update_entity config lentry target target_entity =
  Lwt_list.iter_s (process_attribution config lentry target_entity)
    target.attributions >>
  Lwt_list.iter_s (process_inclusion config lentry target_entity)
    target.inclusions

let process_entry config target target_type = function
 | `Reference _ -> assert false
 | `Entry ((dn, _) as lentry) ->
    let target_path_str =
      Variable.expand_single config ~lentry target.entity_path in
    let target_path = selector_of_string target_path_str in
    Lwt_log.debug_f "Processing %s => %s" dn target_path_str >>
    (match%lwt Entity.select_opt target_path with
     | None ->
        Lwt_log.info_f "N %s ↦ %s" dn target_path_str >>
        if not config.commit then Lwt.return_unit else
        create_entity target_path target_type >>=
        update_entity config lentry target
     | Some target_entity ->
        Lwt_log.info_f "U %s ↦ %s" dn target_path_str >>
        update_entity config lentry target target_entity)

let process_target config ldap_conn (target_name, target) =
  let filter =
    (match config.ldap_filters, target.ldap_filter with
     | [], tfilter -> tfilter
     | cfilters, `And tfilters -> `And (tfilters @ cfilters)
     | cfilters, tfilter -> `And (tfilter :: cfilters))
  in
  Lwt_log.info_f "LDAP base: %s" target.ldap_base_dn >>
  Lwt_log.info_f "LDAP scope: %s" (Netldapx.string_of_scope target.ldap_scope)>>
  Lwt_log.info_f "LDAP filter: %s" (Netldapx.string_of_filter filter) >>
  let%lwt target_type = Entity_type.required target.entity_type in
  let%lwt lr =
    Lwt_preemptive.detach
      (Netldap.search ldap_conn
        ~base:target.ldap_base_dn
        ~scope:target.ldap_scope
        ~deref_aliases:`Always
        ~size_limit:(Option.get_or 0 target.ldap_size_limit)
        ~time_limit:(Option.get_or 0 target.ldap_time_limit)
        ~types_only:false
        ~filter
        ~attributes:target.ldap_attributes)
      ()
  in
  (match lr#code with
   | `Success ->
      Lwt_list.iter_s (process_entry config target target_type) lr#value
   | `TimeLimitExceeded ->
      Lwt_log.warning_f "Result is incomplete due to time limit." >>
      Lwt_list.iter_s (process_entry config target target_type) lr#partial_value
   | `SizeLimitExceeded ->
      Lwt_log.warning_f "Result is incomplete due to size limit." >>
      Lwt_list.iter_s (process_entry config target target_type) lr#partial_value
   | _ ->
      Lwt_log.error_f "LDAP search for target %s failed: %s"
        target_name lr#diag_msg)

let process config =
  let%lwt ldap_conn = Lwt_preemptive.detach connect config in
  Lwt_list.iter_s (process_target config ldap_conn)
                  (Dict.bindings config.targets) >>
  Lwt_log.info "Done."
