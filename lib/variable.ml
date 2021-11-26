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
open Unprime_list

let route_regexp re mapping x =
  (match Re.exec_opt re x with
   | None -> None
   | Some g ->
      let rec loop group_count = function
       | [] -> assert false
       | (mark, ng, y) :: mapping ->
          let lookup var =
            (try Some (Re.Group.get g (group_count + int_of_string var)) with
             | Not_found ->
                Fmt.failwith "Reference to unmatched group in %a." Template.pp y
             | Failure _ -> None) in
          if Re.Mark.test g mark then Template.partial_expand lookup y else
          loop (group_count + ng) mapping
      in
      Some (loop 0 mapping))

let rec lookup_multi cfg ?lentry var =
  (match String.split_on_char ':' var with
   | ["env"; var] ->
      (match String.split_on_char '=' var with
       | [var] ->
          (try [Unix.getenv var] with Not_found -> [])
       | [var; default] ->
          (try [Unix.getenv var] with Not_found -> [default])
       | _ ->
          Fmt.failwith "Multiple defaults in environment variable reference.")
   | ["var"; var] | [var] ->
      (match Dict.find var cfg.bindings with
       | exception Not_found ->
          Fmt.failwith "Undefined variable %s." var
       | Ldap_attribute at ->
          (match lentry with
           | Some lentry ->
              (try List.assoc at (snd lentry) with Not_found -> [])
           | None ->
              Fmt.failwith
                "LDAP lookups like %s are only valid in target contexts." var)
       | Map_literal (d, tmpl, true) ->
          expand_multi cfg ?lentry tmpl
            |> List.map (fun x -> try Dict.find x d with Not_found -> x)
       | Map_literal (d, tmpl, false) ->
          expand_multi cfg ?lentry tmpl
            |> List.filter_map
                (fun x -> try Some (Dict.find x d) with Not_found -> None)
       | Map_regexp (re, mapping, tmpl) ->
          expand_multi cfg ?lentry tmpl
            |> List.filter_map (route_regexp re mapping)
            |> List.flatten_map (expand_multi cfg ?lentry))
   | _ ->
      Fmt.failwith "Invalid variable form %s." var)

and lookup_single cfg ?lentry ~tmpl var =
  (match lookup_multi cfg ?lentry var with
   | [x] -> x
   | [] ->
      Fmt.failwith "Cannot substitute undefined %s into %S."
                   var (Template.to_string tmpl)
   | _ ->
      Fmt.failwith "Cannot substitute multi-valued %s into %S."
                   var (Template.to_string tmpl))

and expand_multi cfg ?lentry tmpl =
  Template.expand_fold
    (fun var f -> List.fold f (lookup_multi cfg ?lentry var))
    List.cons tmpl []

and expand_single cfg ?lentry tmpl =
  Template.expand (lookup_single cfg ?lentry ~tmpl) tmpl
