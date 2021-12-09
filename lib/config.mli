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

type ldap_bind =
  | Ldap_bind_anon
  | Ldap_bind_simple of {dn: string; password: string}
  | Ldap_bind_sasl_gssapi
  [@@deriving show]

type t = {
  ldap_uri: Uri.t;
  ldap_bind: ldap_bind;
  ldap_filters: Netldap.filter list; (* conjuncted with target filters *)
  ldap_update_time_filter: Scope.Ldap_time_filter_cfg.t option;
  min_update_period: Ptime.Span.t;
  ldap_timeout: float option;
  targets: Target.Cfg.t Dict.t;
  scopes: Scope.Cfg.t Dict.t;
  bindings: Variable.extraction Dict.t;
  commit: bool;
  logging: Logging.Cfg.t;
} [@@deriving show]

exception Error of string

val of_inifile : Inifiles.inifile -> t
