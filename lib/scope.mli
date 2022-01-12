(* subsocia-sync-ldap - Synchonizing LDAP to Subsocia
 * Copyright (C) 2017--2021  University of Copenhagen
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

(** Scope of Processing *)

type ldap_attribute_type = Netldapx.attribute_type
type ldap_dn = string
type ldap_filter = Netldap.filter
type ldap_filter_template = Netldapx.Filter_template.t

type time = Ptime.t * Ptime.tz_offset_s
type period = time option * time option
type error = [
  | `Search_failed | `Time_limit_exceeded | `Size_limit_exceeded
  | `Msg of string
]

module Ldap_time_filter_cfg : sig
  type t = {
    start_template: ldap_filter_template;
    stop_template: ldap_filter_template;
    time_format: string;
    time_zone: int option;
  }
end

module Cfg : sig
  type t = {
    ldap_base_dn: ldap_dn;
    ldap_scope: Netldap.scope;
    ldap_filters: Netldap.filter list;
    ldap_update_time_filter: Ldap_time_filter_cfg.t option;
    ldap_partition_attribute_type: ldap_attribute_type option;
    ldap_size_limit: int option;
    ldap_time_limit: int option;
    partial_is_ok: bool;
    target_names: string list;
  }
end

val process :
  commit: bool ->
  period: period ->
  ldap_conn: Netldap.ldap_connection ->
  global_ldap_filters:  Netldap.filter list ->
  default_ldap_update_time_filter: Ldap_time_filter_cfg.t option ->
  min_update_period: Ptime.Span.t ->
  scope_name: string ->
  scope_cfg: Cfg.t ->
  targets: Target.t list ->
  ?csn_directory_state: Csn_state.Directory.t ->
  unit -> (unit, error) result Lwt.t
