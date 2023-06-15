(* subsocia-sync-ldap - Synchonizing LDAP to Subsocia
 * Copyright (C) 2018--2023  University of Copenhagen
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

module Verbosity = struct
  type t = {
    global: Logs.level option option;
    per_source: (string * Logs.level option) list;
  }

  let default = {global = None; per_source = []}

  let level_of_string_exn level_name =
    (match Logs.level_of_string level_name with
     | Ok level -> level
     | Error (`Msg msg) -> failwith msg)

  let of_string s =
    try
      let parse_pair x =
        let i = String.rindex x ':' in
        let level_name = String.sub x (i + 1) (String.length x - i - 1) in
        (String.sub x 0 i, level_of_string_exn level_name)
      in
      (match String.split_on_char ',' s with
       | [] -> Ok {global = None; per_source = []}
       | "" :: xs -> Ok {global = None; per_source = List.map parse_pair xs}
       | x :: xs when not (String.contains x ':') ->
          Ok {global = Some (level_of_string_exn x);
              per_source = List.map parse_pair xs}
       | xs -> Ok {global = None; per_source = List.map parse_pair xs})
    with
     | Failure msg -> Error (`Msg ("invalid verbosity: " ^ msg))
     | Not_found -> Error (`Msg "missing colon in verbosity specification")

  let of_string_exn s =
    (match of_string s with Ok v -> v | Error (`Msg msg) -> failwith msg)

  let pp =
    let open Fmt in
    let level = option ~none:(const string "quiet") Logs.pp_level in
    using (fun {global; _} -> global) (option level) ++
    using (fun {per_source; _} -> per_source)
      (list (comma ++ pair ~sep:(const string ":") string level))

  let setup verbosity =
    let setup_src src =
      Option.iter
        (Logs.Src.set_level src)
        (List.assoc_opt (Logs.Src.name src) verbosity.per_source)
    in
    Option.iter Logs.set_level verbosity.global;
    List.iter setup_src (Logs.Src.list ())
end

module Cfg = struct

  type reporter =
    | Stdio_reporter
    | File_reporter of Template.t

  type t = {
    verbosity: Verbosity.t;
    reporters: reporter list;
  }

end

open Cfg

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

let setup_logging bindings cfg =

  let open_log = function
   | Stdio_reporter -> Lwt.return [(Lwt_io.stdout, Lwt_io.stderr)]
   | File_reporter file_name_tmpl ->
      let aux file_name =
        let* oc =
          Lwt_io.open_file
            ~flags:Unix.[O_APPEND; O_WRONLY; O_CREAT]
            ~mode:Lwt_io.output file_name
        in
        Lwt.return (oc, oc)
      in
      Lwt_list.map_p aux (Template_env.expand_multi bindings file_name_tmpl)
  in
  let* log_channels =
    Lwt_list.map_p open_log cfg.reporters >|= List.flatten in
  Logs.set_reporter (logs_reporter log_channels);
  Verbosity.setup cfg.verbosity;
  Lwt.return_unit
