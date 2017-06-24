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

open Unprime_option
module Dict = Map.Make (String)

type ldap_attribute_type = string
type ldap_dn = string
type ldap_filter = Netldap.filter

type extract =
  | Ldap_attribute of ldap_attribute_type
  | Map_literal of string Dict.t * Template.t * bool
  | Map_regexp of Re.re * (Re.Mark.t * Template.t) list * Template.t
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
  ldap_base_dn: ldap_dn;
  ldap_scope: Netldap.scope;
  ldap_filter: Netldap.filter;
  ldap_attributes: string list;
  ldap_size_limit: int option;
  ldap_time_limit: int option;
  entity_type: string;
  entity_path: Template.t;
  inclusions: inclusion list;
  attributions: attribution list;
} [@@deriving show]

type t = {
  ldap_uri: Uri.t;
  ldap_sasl_dn: string;
  ldap_sasl_user: string;
  ldap_filters: Netldap.filter list; (* conjuncted with target filters *)
  subsocia_db_uri: Uri.t;
  targets: target Dict.t;
  bindings: extract Dict.t;
  commit: bool;
} [@@deriving show]

exception Error of string

let error_f fmt = Printf.ksprintf (fun msg -> raise (Error msg)) fmt

(* Config Builders *)

let add_target target_name target cfg =
  if Dict.mem target_name cfg.targets then
    error_f "Target %s is already defined." target_name
  else
    {cfg with targets = Dict.add target_name target cfg.targets}

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

let get conv ini section var =
  try conv (ini#getval section var) with
   | Inifiles.Invalid_element _ ->
      error_f "Missing required setting %s in section %s." var section
   | Inifiles.Invalid_section _ ->
      error_f "Missing required section %s." section
   | Invalid_argument _ | Failure _ ->
      error_f "Invalid value for %s in section %s." var section

let get_opt conv ini section var =
  try Some (conv (ini#getval section var)) with
   | Inifiles.Invalid_element _ | Inifiles.Invalid_section _ ->
      None
   | Invalid_argument _ | Failure _ ->
      error_f "Invalid value for %s in section %s." var section

let get_list conv ini section var =
  try List.map conv (ini#getaval section var) with
   | Inifiles.Invalid_element _ | Inifiles.Invalid_section _ ->
      []
   | Invalid_argument _ | Failure _ | Not_found ->
      error_f "Invalid value for %s in section %s." var section

let get_bool ini = get bool_of_string ini
let get_string ini = get (fun x -> x) ini
let get_string_opt ini = get_opt (fun x -> x) ini
let get_uri ini = get Uri.of_string ini

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

let mapping_of_string =
  fun conv input ->
    (match Angstrom.parse_only mapping_parser (`String input) with
     | Ok m -> conv m
     | Error msg -> invalid_arg msg)

let get_mapping conv ini section var =
  get_list (mapping_of_string conv) ini section var

let get_regexp_mapping ini section var =
  let rms =
    get_mapping
      (fun (k, v) ->
        let (mark, re) = Re.mark (Re_pcre.re k) in
        (re, (mark, Template.of_string v)))
      ini section var
  in
  (Re.compile (Re.alt (List.map fst rms)), List.map snd rms)

let get_literal_mapping ini section var =
  get_mapping (fun (k, v) -> (k, v)) ini section var
    |> List.fold_left (fun dict (k, v) -> Dict.add k v dict) Dict.empty

(* Config from .ini *)

let target_of_inifile ini section = {
  ldap_base_dn = get_string ini section "ldap_base_dn";
  ldap_scope =
    Option.get_or `Sub
      (get_opt Netldapx.scope_of_string ini section "ldap_scope");
  ldap_filter = get Netldapx.filter_of_string ini section "ldap_filter";
  ldap_attributes = get_list (fun s -> s) ini section "ldap_attribute";
  ldap_size_limit = get_opt int_of_string ini section "ldap_size_limit";
  ldap_time_limit = get_opt int_of_string ini section "ldap_time_limit";
  entity_type = get_string ini section "entity_type";
  entity_path = get Template.of_string ini section "entity_path";
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
  let input = get_string ini section "input" in
  let mapping = get_literal_mapping ini section "case" in
  let passthrough = get_bool ini section "passthrough" in
  Map_literal (mapping, Template.of_string input, passthrough)

let regexp_mapping_of_inifile ini section =
  let input = get_string ini section "input" in
  let re, mapping = get_regexp_mapping ini section "case" in
  Map_regexp (re, mapping, Template.of_string input)

let ldap_attribute_of_inifile ini section =
  let ldap_attribute_type = get_string ini section "ldap_attribute_type" in
  Ldap_attribute ldap_attribute_type

let extract_of_inifile ini section =
  (match get_string ini section "method" with
   | "mapping" -> literal_mapping_of_inifile ini section
   | "regexp" -> regexp_mapping_of_inifile ini section
   | "ldap_attribute" -> ldap_attribute_of_inifile ini section
   | meth -> error_f "Invalid variable method %s." meth)

let of_inifile ini =
  let cfg = {
    ldap_uri = get_uri ini "connection" "ldap_uri";
    ldap_sasl_dn = get_string ini "connection" "ldap_sasl_dn";
    ldap_sasl_user = get_string ini "connection" "ldap_sasl_user";
    ldap_filters =
      get_list Netldapx.filter_of_string ini "connection" "ldap_filter";
    subsocia_db_uri = get_uri ini "connection" "ldap_uri";
    bindings = Dict.empty;
    targets = Dict.empty;
    commit = get bool_of_string ini "connection" "commit";
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
     | ["target"; _] | ["connection"] -> cfg
     | _ -> error_f "Unexpected section %s." section)
  in
  let cfg = List.fold_left process_target_section cfg ini#sects in
  let cfg = List.fold_left process_nontarget_section cfg ini#sects in
  cfg
