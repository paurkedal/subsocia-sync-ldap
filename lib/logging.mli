(* subsocia-sync-ldap - Synchonizing LDAP to Subsocia
 * Copyright (C) 2018  University of Copenhagen
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

  type reporter =
    | Stdio_reporter
    | File_reporter of Template.t

  type t = {
    level: Logs.level option;
    reporters: reporter list;
  }

end

module Log : Logs_lwt.LOG
module Commit_log : Logs_lwt.LOG

val setup_logging : Variable.bindings -> Cfg.t -> unit Lwt.t
