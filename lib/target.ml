(* subsocia-sync-ldap - Synchonizing LDAP to Subsocia
 * Copyright (C) 2021  University of Copenhagen
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
open Subsocia_common
open Unprime_list

module Cfg = struct

  type inclusion = {
    relax_super: Template.t option;
    force_super: Template.t;
  }

  type attribution = {
    source: Template.t;
    replace: (string * Template.t) list;
  }

  type t = {
    subsocia_uri: Template.t;
    ldap_attributes: string list;
    entity_type: string;
    entity_path: Template.t;
    create_if_exists: Template.t option;
    inclusions: inclusion list;
    attributions: attribution list;
  }

end

let selector_of_string s =
  (try Subsocia_selector.selector_of_string s with
   | Invalid_argument _ -> Fmt.failwith "Invalid selector %s." s)

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

module type S = sig
  val ldap_attributes : string list
  val process : commit: bool -> Netldap.search_result list -> unit Lwt.t
end

module type ARG = sig
  val bindings : Variable.bindings
  val cfg : Cfg.t
end

module Make (Arg : ARG) () : S = struct
  open Arg
  open Cfg

  let uri = Uri.of_string (Variable.expand_single bindings cfg.subsocia_uri)

  let ldap_attributes = cfg.ldap_attributes

  module Subsocia_conn = (val Subsocia_connection.connect uri)
  open Subsocia_conn

  type attribute_binding =
   | Attribute_binding : 'a Attribute_type.t * 'a Values.t -> attribute_binding

  let create_entity target_path target_type =
    let pfx, aconj = Subsocia_selector.add_selector_of_selector target_path in
    let* pfx_entity =
      (match pfx with
       | None -> Entity.get_root ()
       | Some pfx -> Entity.select_one pfx)
    in
    let resolve (atn, values) =
      let* Attribute_type.Any at = Attribute_type.any_of_name_exn atn in
      let vt = Attribute_type.value_type at in
      let values = List.map (Value.typed_of_string vt) values in
      Lwt.return (Attribute_binding (at, Values.of_elements vt values))
    in
    let* aconj = Lwt_list.map_s resolve (String_map.bindings aconj) in
    let* entity = Entity.create target_type in
    let+ () =
      Lwt_list.iter_s
        (fun (Attribute_binding (at, values)) ->
          Entity.set_values at values pfx_entity entity) aconj
    in
    entity

  let process_attribution ~commit ~start_update
        lentry target_entity attribution =
    let source_path_str =
      Variable.expand_single bindings ~lentry attribution.source in
    let source_path = selector_of_string source_path_str in
    let* source_entity = Entity.select_one source_path in
    let replace (atn, tmpl) =
      let* Attribute_type.Any at = Attribute_type.any_of_name_exn atn in
      let vt = Attribute_type.value_type at in
      let values_str = Variable.expand_multi bindings ~lentry tmpl in
      let values = List.map (Value.typed_of_string vt) values_str in
      let values = Values.of_elements vt values in
      let* old_values = Entity.get_values at source_entity target_entity in
      if Values.elements values = Values.elements old_values then
        Lwt.return_unit else
      Lazy.force start_update >>= fun () ->
      Commit_log.app (fun m ->
        m "- %s %s ↦ %s" atn
          (Values.to_json_string vt old_values)
          (Values.to_json_string vt values)) >>= fun () ->
      if not commit then Lwt.return_unit else
      Entity.set_values at values source_entity target_entity
    in
    Lwt_list.iter_s replace attribution.replace

  let select_or_warn sel =
    (match%lwt Entity.select_opt sel with
     | None ->
        Log.warn (fun m ->
          m "Cannot find %s."
            (Subsocia_selector.string_of_selector sel)) >>= fun () ->
        Lwt.return_none
     | Some ent ->
        Lwt.return_some ent)

  let process_inclusion ~commit ~start_update lentry target_entity inclusion =
    let force_paths =
      Variable.expand_multi bindings ~lentry inclusion.force_super in
    let force_paths = List.map selector_of_string force_paths in
    let* force_entities = Lwt_list.filter_map_s select_or_warn force_paths in

    let force_super super_entity =
      if%lwt not =|< Entity.is_sub target_entity super_entity then begin
        let* super_name = Entity.display_name super_entity in
        Lazy.force start_update >>= fun () ->
        Commit_log.app (fun m -> m "≼ %s" super_name) >>= fun () ->
        if not commit then Lwt.return_unit else
        Entity.force_dsub target_entity super_entity
      end
    in

    let relax_super super_entity =
      if%lwt Entity.is_sub target_entity super_entity then begin
        let* super_name = Entity.display_name super_entity in
        Lazy.force start_update >>= fun () ->
        Commit_log.app (fun m -> m "⋠ %s" super_name) >>= fun () ->
        if not commit then Lwt.return_unit else
        Entity.relax_dsub target_entity super_entity
      end
    in

    Lwt_list.iter_s force_super force_entities >>= fun () ->
    (match inclusion.relax_super with
     | None -> Lwt.return_unit
     | Some relax_paths ->
        let relax_paths = Variable.expand_multi bindings ~lentry relax_paths in
        let relax_paths = List.map selector_of_string relax_paths in
        let* relax_entities = Lwt_list.map_s Entity.select relax_paths in
        let relax_entities = Entity.Set.empty
          |> List.fold Entity.Set.union relax_entities
          |> List.fold Entity.Set.remove force_entities
        in
        Entity.Set.iter_s relax_super relax_entities)

  let update_entity ~commit ?(start_update = lazy Lwt.return_unit)
                    lentry cfg target_entity =
    Lwt_list.iter_s
      (process_attribution ~commit ~start_update lentry target_entity)
      cfg.attributions >>= fun () ->
    Lwt_list.iter_s
      (process_inclusion ~commit ~start_update lentry target_entity)
      cfg.inclusions

  let check_create_condition lentry =
    (match cfg.create_if_exists with
     | None -> true
     | Some tmpl -> Variable.expand_multi bindings ~lentry tmpl != [])

  let process_entry ~commit stats cfg target_type = function
   | `Reference _ -> assert false
   | `Entry ((dn, _) as lentry) ->
      let target_path_str =
        Variable.expand_single bindings ~lentry cfg.entity_path in
      let target_path = selector_of_string target_path_str in
      Log.debug (fun m -> m "Processing %s => %s" dn target_path_str)
        >>= fun () ->
      (match%lwt Entity.select_opt target_path with
       | None ->
          if check_create_condition lentry then begin
            Stats.(stats.create_count <- stats.create_count + 1);
            Commit_log.app (fun m -> m "N %s ↦ %s" dn target_path_str)
              >>= fun () ->
            if not commit then Lwt.return_unit else
            create_entity target_path target_type >>=
            update_entity ~commit lentry cfg
          end else Lwt.return_unit
       | Some target_entity ->
          let start_update = lazy begin
            Stats.(stats.update_count <- stats.update_count + 1);
            Commit_log.app (fun m -> m "U %s ↦ %s" dn target_path_str)
          end in
          update_entity ~commit ~start_update lentry cfg target_entity)

  let process ~commit lr_value =
    let stats = Stats.create () in
    let* target_type = Entity_type.of_name_exn cfg.entity_type in
    Lwt_list.iter_s (process_entry ~commit stats cfg target_type) lr_value
      >>= fun () ->
    Log.info (fun m -> m
      "Processed %d LDAP entries, %a." (List.length lr_value) Stats.pp stats)
end

type t = (module S)

let connect bindings cfg =
  (module Make (struct let bindings = bindings let cfg = cfg end) () : S)

let ldap_attributes (module C : S) = C.ldap_attributes

let process ~commit (module C : S) entries = C.process ~commit entries
