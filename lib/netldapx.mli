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

(** Supplements to [Netldap]. *)

type filter = Netldap.filter

val scope_of_string : string -> Netldap.scope
val string_of_scope : Netldap.scope -> string

val filter_of_string : string -> Netldap.filter
val string_of_filter : Netldap.filter -> string

module Filter_template : sig
  type t
  val of_string : string -> t
  val to_string : t -> string
  val neg : t -> t
  val expand : (Template.var -> string) -> t -> filter
end

type ldap_entry = string * (string * string list) list
