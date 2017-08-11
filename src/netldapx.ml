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

open Ldap_types

let scope_of_string = function
 | "base" -> `Base
 | "one" -> `One
 | "sub" | "subtree" -> `Sub
 | noscope -> failwith ("Invalid LDAP scope " ^ noscope)

let string_of_scope = function
 | `Base -> "base"
 | `One -> "one"
 | `Sub -> "sub"

let rec filter_of_ocamldapfilter = function
 | `And zs -> `And (List.map filter_of_ocamldapfilter zs)
 | `Or zs -> `Or (List.map filter_of_ocamldapfilter zs)
 | `Not z -> `Not (filter_of_ocamldapfilter z)
 | `EqualityMatch a -> `Equality_match (a.attributeDesc, a.assertionValue)
 | `Substrings a ->
    let to_opt = function
     | [] -> None
     | [x] -> Some x
     | xs -> Some (String.concat "" xs) (* TODO: Check ocamldap code. *)
    in
    `Substrings (a.attrtype,
                 to_opt a.substrings.substr_initial,
                 a.substrings.substr_any,
                 to_opt a.substrings.substr_final)
 | `GreaterOrEqual a -> `Greater_or_equal (a.attributeDesc, a.assertionValue)
 | `LessOrEqual a -> `Less_or_equal (a.attributeDesc, a.assertionValue)
 | `Present atn -> `Present atn
 | `ApproxMatch a -> `Approx_match (a.attributeDesc, a.assertionValue)
 | `ExtensibleMatch a ->
    `Extensible_match (a.matchingRule, (* TODO: Check. *)
                       a.ruletype,     (* TODO: Check. *)
                       a.matchValue,
                       a.dnAttributes)

let rec ocamldapfilter_of_filter = function
 | `And zs -> `And (List.map ocamldapfilter_of_filter zs)
 | `Or zs -> `Or (List.map ocamldapfilter_of_filter zs)
 | `Not z -> `Not (ocamldapfilter_of_filter z)
 | `Equality_match (attributeDesc, assertionValue) ->
    `EqualityMatch {attributeDesc; assertionValue}
 | `Substrings (attrtype, substr_initial, substr_any, substr_final) ->
    let substr_initial = match substr_initial with None -> [] | Some x -> [x] in
    let substr_final = match substr_final with None -> [] | Some x -> [x] in
    let substrings = {substr_initial; substr_any; substr_final} in
    `Substrings {attrtype; substrings} (* TODO: Check *)
 | `Greater_or_equal (attributeDesc, assertionValue) ->
    `GreaterOrEqual {attributeDesc; assertionValue}
 | `Less_or_equal (attributeDesc, assertionValue) ->
    `LessOrEqual {attributeDesc; assertionValue}
 | `Present atn -> `Present atn
 | `Approx_match (attributeDesc, assertionValue) ->
    `ApproxMatch {attributeDesc; assertionValue}
 | `Extensible_match (matchingRule, ruletype, matchValue, dnAttributes) ->
    (* TODO: Check *)
    `ExtensibleMatch {matchingRule; ruletype; matchValue; dnAttributes}

let filter_of_string s = filter_of_ocamldapfilter (Ldap_filter.of_string s)
let string_of_filter z = Ldap_filter.to_string (ocamldapfilter_of_filter z)

type ldap_entry = string * (string * string list) list
