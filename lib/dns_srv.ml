(* subsocia-sync-ldap - Synchonizing LDAP to Subsocia
 * Copyright (C) 2023  University of Copenhagen
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
let ( let+? ) = Lwt_result.Syntax.( let+ )

module Log = (val Logs.src_log (Logs.Src.create "subsocia-sync-ldap.dns"))

let simplify_error = function
 | (Ok _ | Error (`Msg _)) as r -> r
 | Error (`No_data (domain, soa)) ->
    Fmt.error_msg "No services for %a returned from %a."
      Domain_name.pp domain Dns.Soa.pp soa
 | Error (`No_domain (domain, soa)) ->
    Fmt.error_msg "Domain %a not found at %a."
      Domain_name.pp domain Dns.Soa.pp soa

let parse_ldap_srv_path scheme path =
  let extract_dc comp =
    (match String.split_on_char '=' comp with
     | ["dc"; dc] -> dc
     | _ -> failwith "parse_ldap_srv_path_exn")
  in
  (match String.split_on_char '/' path with
   | [""; dn] ->
      (try
        let dcs = List.map extract_dc (String.split_on_char ',' dn) in
        let dcs = ("_" ^ scheme) :: "_tcp" :: dcs in
        Ok (Domain_name.of_string_exn (String.concat "." dcs))
       with
        | Failure _ -> Error (`Msg "Invalid DN in LDAP URI."))
   | _ ->
      Error (`Msg "Invalid LDAP URI, expecting a single path level."))

let resolve_ldap_uri uri =
  let happy_eyeballs = Happy_eyeballs_lwt.create () in
  let dns_client = Dns_client_lwt.create happy_eyeballs in
  let uri_of_srv (srv : Dns.Srv.t) =
    let target = Domain_name.to_string srv.target in
    Log.debug (fun m -> m "%a resolves to %s." Uri.pp uri target);
    Uri.with_uri ~port:(Some srv.port) ~host:(Some target) ~path:None uri
  in
  let lookup domain =
    Log.debug (fun m -> m "Checking SRV records for %a." Domain_name.pp domain);
    let+? _ttl, srvs =
      Dns_client_lwt.get_resource_record dns_client Dns.Rr_map.Srv domain
        >|= simplify_error
    in
    (* Though not documented, the sort order is by priority, weight, port, then
     * host in the current ocaml-dns implementation, which makes sense. *)
    List.map uri_of_srv (Dns.Rr_map.Srv_set.elements srvs)
  in
  (match Uri.scheme uri, Uri.host uri, Uri.path uri with
   | _, _, ("" | "/") -> Lwt.return_ok [uri]
   | Some ("ldap" | "ldaps" as scheme), (None | Some ""), path ->
      (match parse_ldap_srv_path scheme path with
       | Ok domain -> lookup domain
       | Error _ as r -> Lwt.return r)
   | _ ->
      Lwt.return_ok [uri])
