(* Nimbus - Project Application System
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

let rec of_ldap_filter = function
 | `And zs -> `And (List.map of_ldap_filter zs)
 | `Or zs -> `Or (List.map of_ldap_filter zs)
 | `Not z -> `Not (of_ldap_filter z)
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

let of_string s = of_ldap_filter (Ldap_filter.of_string s)
