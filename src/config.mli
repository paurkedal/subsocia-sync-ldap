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

(** Configuration *)

module Dict : Map.S with type key = string

type ldap_attribute_type = string
type ldap_dn = string
type ldap_filter = Netldap.filter
type ldap_filter_template = Netldapx.Filter_template.t

type extract =
  | Ldap_attribute of ldap_attribute_type
  | Map_literal of string Dict.t * Template.t * bool
  | Map_regexp of Re.re * (Re.Mark.t * int * Template.t) list * Template.t
  [@@deriving show]

type inclusion = {
  relax_super: Template.t option;
  force_super: Template.t;
} [@@deriving show]

type attribution = {
  source: Template.t;
  replace: (string * Template.t) list;
} [@@deriving show]

type target = {
  subsocia_uri: Template.t;
  ldap_attributes: string list;
  entity_type: string;
  entity_path: Template.t;
  create_if_exists: Template.t option;
  inclusions: inclusion list;
  attributions: attribution list;
} [@@deriving show]

type scope = {
  ldap_base_dn: ldap_dn;
  ldap_scope: Netldap.scope;
  ldap_filters: Netldap.filter list;
  ldap_update_time_filter:
    (ldap_filter_template * ldap_filter_template * string * int option) option;
  ldap_partition_attribute_type: ldap_attribute_type option;
  ldap_size_limit: int option;
  ldap_time_limit: int option;
  partial_is_ok: bool;
  target_names: string list;
} [@@deriving show]

type log_reporter =
  | Stdio_reporter
  | File_reporter of Template.t

type ldap_bind =
  | Ldap_bind_anon
  | Ldap_bind_simple of {dn: string; password: string}
  | Ldap_bind_sasl_gssapi
  [@@deriving show]

type t = {
  ldap_uri: Uri.t;
  ldap_bind: ldap_bind;
  ldap_filters: Netldap.filter list; (* conjuncted with target filters *)
  ldap_update_time_filter:
    (ldap_filter_template * ldap_filter_template * string * int option) option;
  min_update_period: Ptime.Span.t;
  ldap_timeout: float option;
  targets: target Dict.t;
  scopes: scope Dict.t;
  bindings: extract Dict.t;
  commit: bool;
  log_level: Logs.level option;
  log_reporters: log_reporter list;
} [@@deriving show]

exception Error of string

val of_inifile : Inifiles.inifile -> t
