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

type var = string

type frag =
 | L of string
 | V of var

type t = frag list

let literal s = [L s]

let of_string =
  let re = Re_pcre.regexp {q|\$\{([^{}]+)\}|q} in
  let is_noop = function L "" -> false | _ -> true in
  let to_frag = function `Text s -> L s | `Delim g -> V (Re.Group.get g 1) in
  List.filter is_noop % List.map to_frag % Re.split_full re

let to_string =
  String.concat "" % List.map (function L s -> s | V var -> "${"^var^"}")

let expand lookup =
  let expand_frag = function L s -> s | V var -> lookup var in
  String.concat "" % List.map expand_frag

let expand_fold lookup f =
  let rec loop strs = function
   | [] -> f (String.concat "" (List.rev strs))
   | L s :: frags -> loop (s :: strs) frags
   | V var :: frags -> lookup var (fun s -> loop (s :: strs) frags)
  in
  loop []
