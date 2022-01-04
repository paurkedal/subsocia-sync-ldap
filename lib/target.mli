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

module Cfg : sig

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

type t

val connect : Variable.bindings -> Cfg.t -> t

val ldap_attributes : t -> string list

val process : commit: bool -> t -> Netldap.search_result list -> unit Lwt.t
