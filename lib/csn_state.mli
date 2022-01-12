(* subsocia-sync-ldap - Synchonizing LDAP to Subsocia
 * Copyright (C) 2022  University of Copenhagen
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

module Cfg : sig

  type t = {
    csn_state_dir: string;
    csn_context_base_dn: string;
    csn_context_attribute_type: string;
    csn_entry_attribute_type: string;
  }

end

module Directory : sig
  type t

  val load : Cfg.t -> string -> Netldap.ldap_connection -> t Lwt.t

  val context_csn : t -> string
end

type t

val load : Directory.t -> Netldap.filter -> (t, [> `Msg of string]) result Lwt.t

val save : commit: bool -> t -> (unit, [> `Msg of string]) result Lwt.t

val filter : t -> Netldap.filter
