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

(** Simple templates with multi-valued expansion. *)

type var = string
type t

val literal : string -> t

val of_string : string -> t
(** [of_string s] is the template represented by [s]. *)

val to_string : t -> string

val expand : (var -> string) -> t -> string

val expand_fold :
  (var -> (string -> 'a -> 'a) -> 'a -> 'a) ->
  (string -> 'a -> 'a) ->
  t -> 'a -> 'a
(** [expand_fold lookup f tmpl] is the composition of [f content] for each
    [content] produced from [tmpl] by combinatorically instantiating the
    variables according to [lookup], where [lookup v g] is the composition of [g
    x] over values [x] of [v]. *)
