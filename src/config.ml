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

open Unprime
open Unprime_option
module Dict = Map.Make (String)

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

let error_f fmt = Printf.ksprintf (fun msg -> raise (Error msg)) fmt

(* Config Builders *)

let add_target target_name target cfg =
  if Dict.mem target_name cfg.targets then
    error_f "Target %s is already defined." target_name else
  {cfg with targets = Dict.add target_name target cfg.targets}

let add_scope scope_name scope cfg =
  if Dict.mem scope_name cfg.scopes then
    error_f "Scope %s is already defined." scope_name;
  scope.target_names |> List.iter begin fun target_name ->
    if not (Dict.mem target_name cfg.targets) then
      error_f "Scope %s refers to undefined target %s." scope_name target_name
  end;
  {cfg with scopes = Dict.add scope_name scope cfg.scopes}

let add_attribution target_name attribution_name attribution cfg =
  try
    let target = Dict.find target_name cfg.targets in
    let target =
      {target with attributions = attribution :: target.attributions} in
    {cfg with targets = Dict.add target_name target cfg.targets}
  with Not_found ->
    error_f "Target %s for attribution %s is not defined."
            target_name attribution_name

let add_inclusion target_name inclusion_name inclusion cfg =
  try
    let target = Dict.find target_name cfg.targets in
    let target = {target with inclusions = inclusion :: target.inclusions} in
    {cfg with targets = Dict.add target_name target cfg.targets}
  with Not_found ->
    error_f "Target %s for inclusion %s is not defined."
            target_name inclusion_name

let add_binding variable extract cfg =
  if Dict.mem variable cfg.bindings then
    error_f "Multiple definitions of %s." variable
  else
    {cfg with bindings = Dict.add variable extract cfg.bindings}

(* Inifile Getters and Parsers *)

let get ?default conv ini section var =
  try conv (ini#getval section var) with
   | Inifiles.Invalid_element _ | Inifiles.Invalid_section _ ->
      (match default with
       | Some default ->
          default
       | None ->
          error_f "Missing required setting %s in section %s." var section)
   | Invalid_argument _ | Failure _ ->
      let value = ini#getval section var in
      error_f "Invalid value %S for %s in section %s." value var section

let get_opt ?default conv ini section var =
  try Some (conv (ini#getval section var)) with
   | Inifiles.Invalid_element _ | Inifiles.Invalid_section _ ->
      default
   | Invalid_argument _ | Failure _ ->
      let value = ini#getval section var in
      error_f "Invalid value %S for %s in section %s." value var section

let get_list ?(default = []) conv ini section var =
  try List.map conv (ini#getaval section var) with
   | Inifiles.Invalid_element _ | Inifiles.Invalid_section _ ->
      default
   | Invalid_argument _ | Failure _ | Not_found ->
      let value = ini#getval section var in
      error_f "Invalid value %S for %s in section %s." value var section

let mapping_parser =
  let open Angstrom in
  let str_escape =
    char '\\' *> satisfy (function '"' | '\\' -> true | _ -> false) in
  let str_frag =
        take_while1 (function '\\' | '"' -> false | _ -> true)
    <|> (str_escape >>| String.make 1) in
  let str = char '"' *> (many str_frag >>| String.concat "") <* char '"' in
  let white = skip_while (function ' ' | '\t' | '\n' -> true | _ -> false) in
  let mapsto = white *> string "=>" *> white in
  lift2 (fun k v -> (k, v)) (white *> str <* mapsto) (str <* white)

let mapping_of_string conv input =
  (match Angstrom.(parse_string ~consume:Consume.All) mapping_parser input with
   | Ok m -> conv m
   | Error msg -> invalid_arg msg)

let get_mapping conv ini section var =
  get_list (mapping_of_string conv) ini section var

let pcre_group_count =
  let re = Re.Pcre.regexp {q|\([^?]|q} in
  fun k -> List.length (Re.all re k)

let get_regexp_mapping ini section var =
  let rms =
    get_mapping
      (fun (k, v) ->
        let (mark, re) = Re.mark (Re.Pcre.re k) in
        (re, (mark, pcre_group_count k, Template.of_string v)))
      ini section var
  in
  (Re.compile (Re.alt (List.rev_map fst rms)), List.rev_map snd rms)

let get_literal_mapping ini section var =
  get_mapping (fun (k, v) -> (k, v)) ini section var
    |> List.fold_left (fun dict (k, v) -> Dict.add k v dict) Dict.empty

let ptime_span_of_string s =
  (match Ptime.Span.of_float_s (float_of_string s) with
   | Some t -> t
   | None -> failwith "Invalid duration.")

let time_zone_s_of_string s =
  (match String.split_on_char ':' s with
   | ["UTC"] -> 0
   | [sH; sM] ->
      if sH = "" || (sH.[0] <> '+' && sH.[0] <> '-') then
        error_f "Invalid time zone, expecting ±HH:MM." else
      let tH = int_of_string sH in
      let tM = int_of_string sM in
      if tH <= -24 || tH >= 24 then
        error_f "Time zone hours out of range." else
      if tM <> 0 then
        error_f "Only whole-hour time zones currently supported." else
      tH * 3600 + tM * 60
   | _ ->
      error_f "Invalid time zone, expecting \"±HH:MM\" or \"UTC\".")

(* Config from .ini *)

let target_of_inifile ini section = {
  subsocia_uri = get Template.of_string ini section "subsocia_uri";
  ldap_attributes = get_list (fun s -> s) ini section "ldap_attribute";
  entity_type = get ident ini section "entity_type";
  entity_path = get Template.of_string ini section "entity_path";
  create_if_exists = get_opt Template.of_string ini section "create_if_exists";
  inclusions = [];
  attributions = [];
}

let inclusion_of_inifile ini section = {
  relax_super = get_opt Template.of_string ini section "relax_super";
  force_super = get Template.of_string ini section "force_super";
}

let attribution_of_inifile ini section =
  let attr_of_string s =
    let i = String.index s '=' in
    let n = String.length s in
    let tmpl = Template.of_string (String.sub s (i + 1) (n - i - 1)) in
    (String.sub s 0 i, tmpl)
  in
  {
    source = get Template.of_string ini section "source";
    replace = get_list attr_of_string ini section "replace";
  }

let literal_mapping_of_inifile ini section =
  let input = get ident ini section "input" in
  let mapping = get_literal_mapping ini section "case" in
  let passthrough = get bool_of_string ini section "passthrough" in
  Map_literal (mapping, Template.of_string input, passthrough)

let regexp_mapping_of_inifile ini section =
  let input = get ident ini section "input" in
  let re, mapping = get_regexp_mapping ini section "case" in
  Map_regexp (re, mapping, Template.of_string input)

let ldap_attribute_of_inifile ini section =
  let ldap_attribute_type = get ident ini section "ldap_attribute_type" in
  Ldap_attribute ldap_attribute_type

let extract_of_inifile ini section =
  (match get ident ini section "method" with
   | "mapping" -> literal_mapping_of_inifile ini section
   | "regexp" -> regexp_mapping_of_inifile ini section
   | "ldap_attribute" -> ldap_attribute_of_inifile ini section
   | meth -> error_f "Invalid variable method %s." meth)

let ldap_update_time_filter_of_inifile ini section =
  let time_zone =
    get_opt time_zone_s_of_string ini section "ldap_update_time_zone" in
  (match
    get_opt Netldapx.Filter_template.of_string ini section
      "ldap_update_time_ge_filter",
    get_opt Netldapx.Filter_template.of_string ini section
      "ldap_update_time_lt_filter",
    get_opt ident ini section "ldap_update_time_format"
   with
   | None, None, _ -> None
   | Some _, _, None | _, Some _, None ->
      failwith "Time format must be provided when using time filters."
   | Some qB, Some qE, Some time_format ->
      Some (qB, qE, time_format, time_zone)
   | Some qB, None, Some time_format ->
      Some (qB, Netldapx.Filter_template.neg qB, time_format, time_zone)
   | None, Some qE, Some time_format ->
      Some (Netldapx.Filter_template.neg qE, qE, time_format, time_zone))

let scope_of_inifile ini section = {
  ldap_base_dn = get ident ini section "ldap_base_dn";
  ldap_scope =
    Option.get_or `Sub
      (get_opt Netldapx.scope_of_string ini section "ldap_scope");
  ldap_filters = get_list Netldapx.filter_of_string ini section "ldap_filter";
  ldap_update_time_filter = ldap_update_time_filter_of_inifile ini section;
  ldap_partition_attribute_type =
    get_opt ident ini section "ldap_partition_attribute_type";
  ldap_size_limit = get_opt int_of_string ini section "ldap_size_limit";
  ldap_time_limit = get_opt int_of_string ini section "ldap_time_limit";
  partial_is_ok =
    get ~default:false bool_of_string ini section "partial_is_ok";
  target_names = get_list ident ini section "target";
}

let log_level_of_string s =
  (match Logs.level_of_string s with
   | Ok level -> level
   | Error (`Msg msg) -> failwith msg)

let log_reporters_of_inifile ini =
  (match get_opt Template.of_string ini "logger" "file",
         get_opt bool_of_string ini "logger" "stdio" with
   | None, Some false -> []
   | None, _          -> [Stdio_reporter]
   | Some file, Some true -> [Stdio_reporter; File_reporter file]
   | Some file, _         -> [File_reporter file])

let of_inifile ini =
  let ldap_bind =
    (match get_opt ident ini "connection" "ldap_sasl_mech",
           get_opt ident ini "connection" "ldap_bind_dn" with
     | None, None -> Ldap_bind_anon
     | None, Some dn ->
        let password =
          get ~default:"" ident ini "connection" "ldap_bind_password" in
        Ldap_bind_simple {dn; password}
     | Some "gssapi", None ->
        Ldap_bind_sasl_gssapi
     | Some "gssapi", Some _ ->
        error_f "Choosing the bind DN is unsupported for GSSAPI."
     | Some mech, _ ->
        error_f "Unsupported SASL mechanism %s." mech) in
  let cfg = {
    ldap_uri = get Uri.of_string ini "connection" "ldap_uri";
    ldap_bind;
    ldap_filters =
      get_list Netldapx.filter_of_string ini "connection" "ldap_filter";
    ldap_update_time_filter =
      ldap_update_time_filter_of_inifile ini "connection";
    min_update_period =
      get ptime_span_of_string ~default:(Ptime.Span.of_int_s 1) ini "connection"
          "min_update_period";
    ldap_timeout = get_opt float_of_string ini "connection" "ldap_timeout";
    bindings = Dict.empty;
    targets = Dict.empty;
    scopes = Dict.empty;
    commit = get bool_of_string ini "connection" "commit";
    log_level = get log_level_of_string ~default:None ini "logger" "level";
    log_reporters = log_reporters_of_inifile ini;
  } in
  let process_target_section cfg section =
    (match String.split_on_char ':' section with
     | ["target"; target_name] ->
        add_target target_name (target_of_inifile ini section) cfg
     | _ ->
        cfg)
  in
  let process_nontarget_section cfg section =
    (match String.split_on_char ':' section with
     | ["inclusion"; target_name; inclusion_name] ->
        add_inclusion target_name inclusion_name
          (inclusion_of_inifile ini section) cfg
     | ["attribution"; target_name; attribution_name] ->
        add_attribution target_name attribution_name
          (attribution_of_inifile ini section) cfg
     | ["var"; variable] ->
        add_binding variable (extract_of_inifile ini section) cfg
     | ["scope"; variable] ->
        add_scope variable (scope_of_inifile ini section) cfg
     | ["target"; _] | ["connection"] | ["logger"] -> cfg
     | _ -> error_f "Unexpected section %s." section)
  in
  let cfg = List.fold_left process_target_section cfg ini#sects in
  let cfg = List.fold_left process_nontarget_section cfg ini#sects in
  cfg
