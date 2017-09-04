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

open Printf
open Subsocia_sync_ldap

let failwith_f fmt = ksprintf failwith fmt

let main config_file scopes commit filters =
  let ini =
    try new Inifiles.inifile config_file with
     | Inifiles.Ini_parse_error (line, file) ->
        Printf.eprintf "%s:%d: Parse error.\n" file line;
        exit 65
  in
  let config = Config.of_inifile ini in
  let config = if commit then Config.{config with commit = true} else config in
  let config =
    Config.{config with ldap_filters = config.ldap_filters @ filters} in
  let missing_scopes =
    List.filter (fun name -> not (Config.Dict.mem name config.Config.scopes))
                scopes in
  if missing_scopes <> [] then
    failwith_f "The requested scope %s is not defined in %s."
               (String.concat ", " missing_scopes) config_file;
  let%lwt () =
    (match config.Config.commit, config.Config.commit_log with
     | false, _ | true, None -> Lwt.return_unit
     | true, Some file_name_tmpl ->
        let file_name = Variable.expand_single config file_name_tmpl in
        let%lwt logger = Lwt_log.file ~mode:`Append ~file_name () in
        Lwt_log.default := Lwt_log.broadcast [logger; !Lwt_log.default];
        Lwt.return_unit) in
  (match%lwt Sync.process config ~scopes with
   | Ok () -> Lwt.return 0
   | Error _ -> Lwt.return 69)

module Arg = struct
  include Cmdliner.Arg

  let ldap_filter =
    let parse s =
      try `Ok (Netldapx.filter_of_string s) with
       | Ldap_filter.Invalid_filter (pos, msg) ->
          `Error (sprintf "At char %d: %s" pos msg) in
    let print ppf z =
      Format.pp_print_string ppf (Netldapx.string_of_filter z) in
    (parse, print)
end

module Term = Cmdliner.Term

let main_cmd =
  let config =
    Arg.(required @@ pos 0 (some file) None @@ info ~docv:"CONFIG" []) in
  let commit =
    let doc =
      "Whether to commit the changes to the subsocia database. \
       The defaut value is specified in the configuration file." in
    Arg.(value @@ flag @@ info ~doc ["commit"]) in
  let scope =
    let docv = "SCOPE" in
    let doc = "Process the given scope instead of default." in
    Arg.(value @@ opt_all string ["default"] @@ info ~doc ~docv ["scope"]) in
  let filter =
    let docv = "FILTER" in
    let doc = "Conjunct the LDAP filter collected this far with FILTER." in
    Arg.(value @@ opt_all ldap_filter [] @@ info ~doc ~docv ["filter"]) in
  let term = Term.(const main $ config $ scope $ commit $ filter) in
  let info = Term.info "subsocia-sync-ldap" in
  (term, info)

let () =
  (match Cmdliner.Term.eval main_cmd with
   | `Ok m -> exit (Lwt_main.run m)
   | `Error _ -> exit 64
   | `Help | `Version -> exit 0)
