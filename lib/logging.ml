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

open Lwt.Infix
open Lwt.Syntax

let main_src = Logs.Src.create "subsocia-sync-ldap"
let commit_src = Logs.Src.create "subsocia-sync-ldap.commit"

module Log = (val Logs_lwt.src_log main_src)
module Commit_log = (val Logs_lwt.src_log commit_src)

let logs_reporter log_channels =
  let buf_fmt () =
    let buf = Buffer.create 512 in
    let flush () = let m = Buffer.contents buf in Buffer.reset buf; m in
    (Format.formatter_of_buffer buf, flush)
  in

  let ppf, ppf_flush = buf_fmt () in

  let report _src level ~over k msgf =
    let write _ppf () =
      let msg = ppf_flush () in
      Lwt_list.iter_p
        (match level with
         | Logs.App -> (fun (oc, _) -> Lwt_io.write oc msg)
         | _        -> (fun (_, oc) -> Lwt_io.write oc msg))
        log_channels
    in
    let finish ppf =
      Lwt.async (fun () ->
        Lwt.finalize (write ppf) (fun () -> over (); Lwt.return_unit));
      k ()
    in
    let tz_offset_s = Ptime_clock.current_tz_offset_s () in
    msgf begin fun ?header ?tags:_ fmt ->
      Format.kfprintf finish ppf ("%a %a @[" ^^ fmt ^^ "@]@.")
        (Ptime.pp_human ?tz_offset_s ()) (Ptime_clock.now ())
        Logs.pp_header (level, header)
    end
  in
  {Logs.report}

let setup_logging config =

  let open_log = function
   | Config.Stdio_reporter -> Lwt.return [(Lwt_io.stdout, Lwt_io.stderr)]
   | Config.File_reporter file_name_tmpl ->
      let aux file_name =
        let* oc =
          Lwt_io.open_file
            ~flags:Unix.[O_APPEND; O_WRONLY; O_CREAT]
            ~mode:Lwt_io.output file_name
        in
        Lwt.return (oc, oc)
      in
      Lwt_list.map_p aux (Variable.expand_multi config file_name_tmpl)
  in
  let* log_channels =
    Lwt_list.map_p open_log config.Config.log_reporters >|= List.flatten in
  Logs.set_reporter (logs_reporter log_channels);
  Logs.set_level config.Config.log_level;
  Lwt.return_unit
