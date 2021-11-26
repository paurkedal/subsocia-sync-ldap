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

open Lwt.Infix
open Printf
open Subsocia_sync_ldap
open Unprime_option

let failwith_f fmt = ksprintf failwith fmt

let main config_file scopes commit filters period =

  (* Load and check the configuration file. *)
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

  (* Set up logging. *)
  Logging.setup_logging config >>= fun () ->

  (* Do the synchronization. *)
  (match%lwt Sync.process config ~scopes ~period () with
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

  let ptime =
    let parse s =
      (match Ptime.of_rfc3339 s |> Ptime.rfc3339_error_to_msg with
       | Ok (t, Some tz_offset_s, _) -> `Ok (t, tz_offset_s)
       | Ok (_, None, _) -> `Error "Missing time zone."
       | Error (`Msg msg) -> `Error msg) in
    let print ppf (t, tz_offset_s) = Ptime.pp_rfc3339 ~tz_offset_s () ppf t in
    (parse, print)

  let ptime_interval =
    let parse s =
      (match String.split_on_char '/' s with
       | [sI; ""] ->
          (match fst ptime sI with
           | `Ok tI -> `Ok (Some tI, None)
           | `Error _ as err -> err)
       | [""; sF] ->
          (match fst ptime sF with
           | `Ok tF -> `Ok (None, Some tF)
           | `Error _ as err -> err)
       | [sI; sF] ->
          let nI = String.length sI in
          let nF = String.length sF in
          let convert sI sF =
            (match fst ptime sI, fst ptime sF with
             | `Ok tI, `Ok tF -> `Ok (Some tI, Some tF)
             | `Error msg, _ | _, `Error msg -> `Error msg) in
          if nF > nI then `Error "End time is longer than start time." else
          if nF = nI then convert sI sF else
            (match sI.[nI - nF - 1], sF.[0] with
             | '0'..'9', 'T' | '-', '0'..'9' ->
                convert sI (String.sub sI 0 (nI - nF) ^ sF)
             | _ -> `Error "Invalid specification of end time.")
       | _ -> `Error "Cannot parse time interval.") in
    let print ppf (tI, tF) =
      Option.iter (snd ptime ppf) tI;
      Format.pp_print_char ppf '/';
      Option.iter (snd ptime ppf) tF in
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
  let period =
    let docv = "PERIOD" in
    let doc =
      "Only consider entries updated in this time period. \
       The argument is expected to be an ISO 8601 time interval without \
       time zone, e.g. 2018-06-15T10:30/10:45. \
       The the inital or final time may be empty to indicate no constraint. \
       This requires ldap_time_filter and ldap_time_format to be specified \
       for the selected scope or globally." in
    Arg.(value @@ opt ptime_interval (None, None) @@ info ~doc ~docv ["period"])
  in
  let term = Term.(const main $ config $ scope $ commit $ filter $ period) in
  let info = Term.info "subsocia-sync-ldap" in
  (term, info)

let () =
  Random.self_init ();
  (match Cmdliner.Term.eval main_cmd with
   | `Ok m -> exit (Lwt_main.run m)
   | `Error _ -> exit 64
   | `Help | `Version -> exit 0)
