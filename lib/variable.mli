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

(** Template and Variable Expansion *)

type ldap_attribute_type = Netldapx.attribute_type

type extraction =
  | Ldap_attribute of ldap_attribute_type
  | Map_literal of string Dict.t * Template.t * bool
  | Map_regexp of Re.re * (Re.Mark.t * int * Template.t) list * Template.t

type bindings = extraction Dict.t

val expand_multi :
  bindings -> ?lentry: Netldapx.ldap_entry -> Template.t -> string list

val expand_single :
  bindings -> ?lentry: Netldapx.ldap_entry -> Template.t -> string
