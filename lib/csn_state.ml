(* subsocia-sync-ldap - Synchonizing LDAP to Subsocia
 * Copyright (C) 2022  University of Copenhagen
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
open Unprime_list

open Logging
open Prereq

module Cfg = struct

  type t = {
    csn_state_dir: string;
    csn_context_base_dn: string;
    csn_context_attribute_type: string;
    csn_entry_attribute_type: string;
  }

end

module Directory = struct
  type t = {
    cfg: Cfg.t;
    server_id: string;
    context_csn: string;
  }

  let load cfg server_id ldap_conn =
    let+ lr =
      Lwt_preemptive.detach
        (Netldap.search ldap_conn
          ~base:cfg.Cfg.csn_context_base_dn
          ~scope:`Base
          ~deref_aliases:`Always
          ~size_limit:1
          ~time_limit:0
          ~types_only:false
          ~filter:(`Present "objectClass")
          ~attributes:[cfg.csn_context_attribute_type])
        ()
    in
    let context_csn =
      (match lr#code with
       | `Success ->
          (match lr#value with
           | [] ->
              failwith "No entry found at CSN base."
           | [`Entry (_, attrs)] ->
              (match List.assoc_opt cfg.csn_context_attribute_type attrs with
               | Some (x :: xs) -> List.fold min xs x
               | Some [] -> assert false
               | None -> failwith "CSN attribute not found")
           | _ -> assert false)
       | _ ->
          failwith "Search for CSN failed.")
    in
    {cfg; server_id; context_csn}

  let context_csn dstate = dstate.context_csn
end

type t = {
  scope_descriptor: string;
  dstate: Directory.t;
  path: string;
  mutable done_csn_context: string option;
}

let filter state =
  let at = state.dstate.cfg.csn_entry_attribute_type in
  let ub = `Less_or_equal (at, state.dstate.context_csn) in
  (match state.done_csn_context with
   | Some value -> `And [`Not (`Less_or_equal (at, value)); ub]
   | None -> ub)

let load dstate filter =
  let module H = Mirage_crypto.Hash.SHA224 in
  let scope_descriptor = String.concat " " [
    dstate.Directory.server_id;
    Netldapx.string_of_filter filter;
  ] in
  let `Hex scope_id = scope_descriptor
    |> Cstruct.of_string |> Mirage_crypto.Hash.SHA224.digest
    |> Hex.of_cstruct
  in
  let path = Filename.concat dstate.cfg.csn_state_dir (scope_id ^ ".csn") in
  Log.info (fun f ->
    f "Using CSN file %S for %S" path scope_descriptor) >>= fun () ->
  let+? done_csn_context =
    let read_csn ic =
      let* line = Lwt_io.read_line ic in
      let n = String.length line in
      if n > 5 && String.sub line 0 5 = "CSN: " then begin
        let csn = String.sub line 5 (n - 5) in
        let+ () = Log.debug (fun f -> f "Loaded CSN %S." csn) in
        Ok (Some csn)
      end else begin
        let+ () = Log.err (fun f -> f "CSN file %s is invalid" path) in
        Fmt.error_msg "%s is invalid" path
      end
    in
    Lwt.catch
      (fun () -> Lwt_io.with_file ~mode:Lwt_io.input path read_csn)
      (function
       | Unix.Unix_error (Unix.ENOENT, _, _) ->
          let+ () = Log.info (fun f -> f "CSN file not yet created.") in
          Ok None
       | Unix.Unix_error (err, _, _) ->
          let msg = Unix.error_message err in
          Lwt.return (Fmt.error_msg "Failed to open %s: %s" path msg)
       | exn -> Lwt.fail exn)
  in
  {scope_descriptor; dstate; path; done_csn_context}

let save ~commit state =
  (match state.done_csn_context with
   | Some csn when csn = state.dstate.context_csn ->
      Log.info (fun f -> f "No change to CSN %S." csn) >|= fun () ->
      Ok ()
   | _ ->
      let csn = state.dstate.context_csn in
      Log.info (fun f ->
        f "Updating CSN from %S to %S."
          (Option.value ~default:"" state.done_csn_context) csn) >>= fun () ->
      state.done_csn_context <- Some csn;
      if not commit then Lwt.return_ok () else
      Lwt.catch
        (fun () ->
          let tmp_path = state.path ^ ".new" in
          Lwt_io.with_file ~mode:Lwt_io.output tmp_path begin fun oc ->
            Lwt_io.fprintf oc "CSN: %s\nID: %s\n" csn state.scope_descriptor
          end >>= fun () ->
          Lwt_unix.rename tmp_path state.path >|= fun () ->
          Ok ())
        (function
         | Unix.Unix_error (err, _, _) ->
            let msg = Unix.error_message err in
            Log.err (fun f ->
              f "Failed to save CSN %S to %s: %s" csn state.path msg)
              >|= fun () ->
            Fmt.error_msg "Failed to save CSN %S to %s: %s" csn state.path msg
         | exn -> Lwt.fail exn))
