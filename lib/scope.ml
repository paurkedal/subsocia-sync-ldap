(* subsocia-sync-ldap - LDAP to Subsocia Synchronization
 * Copyright (C) 2017--2021  University of Copenhagen
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
open Unprime_option

open Logging
open Prereq

module String_set = Set.Make (String)

type ldap_attribute_type = Netldapx.attribute_type
type ldap_dn = string
type ldap_filter = Netldap.filter
type ldap_filter_template = Netldapx.Filter_template.t

module Ldap_time_filter_cfg = struct
  type t = {
    start_template: ldap_filter_template;
    stop_template: ldap_filter_template;
    time_format: string;
    time_zone: int option;
  }

  let format_ptime fmt (t, tz_offset_s) tz_offset_s_cfg =
    let zone =
      let tz_s =
        (match tz_offset_s_cfg with
         | None -> tz_offset_s
         | Some tz_offset_s -> tz_offset_s)
      in
      if tz_s mod 60 = 0 then tz_s / 60 else
      failwith "Cannot format time using sub-minute time zone."
    in
    Netdate.create ~zone (Ptime.to_float_s t) |> Netdate.format ~fmt

  let apply {start_template; stop_template; time_format; time_zone} (tI, tF) =
    let mk_time_filter template t =
      let t_str = format_ptime time_format t time_zone in
      Netldapx.Filter_template.expand
        (function
         | "t" -> t_str
         | x -> Fmt.failwith "Undefined variable %s." x)
        template
    in
    [] |> Option.fold (List.cons % mk_time_filter start_template) tI
       |> Option.fold (List.cons % mk_time_filter stop_template) tF
end

module Cfg = struct
  type t = {
    ldap_base_dn: ldap_dn;
    ldap_scope: Netldap.scope;
    ldap_filters: Netldap.filter list;
    ldap_update_time_filter: Ldap_time_filter_cfg.t option;
    ldap_partition_attribute_type: ldap_attribute_type option;
    ldap_size_limit: int option;
    ldap_time_limit: int option;
    partial_is_ok: bool;
    target_names: string list;
  }
end

open Cfg

type time = Ptime.t * Ptime.tz_offset_s
type period = time option * time option

type error = [
  | `Search_failed | `Time_limit_exceeded | `Size_limit_exceeded
  | `Msg of string
]

let pp_ptimetz ppf (t, tz_offset_s) = Ptime.pp_human ~tz_offset_s () ppf t

let pp_period ppf = function
 | None, None -> Format.pp_print_string ppf "(-∞, ∞)"
 | None, Some tF -> Format.fprintf ppf "(-∞, %a)" pp_ptimetz tF
 | Some tI, None -> Format.fprintf ppf "[%a, ∞)" pp_ptimetz tI
 | Some tI, Some tF -> Format.fprintf ppf "[%a, %a)" pp_ptimetz tI pp_ptimetz tF

let add_time_filter ~scope_name ~update_time_filter period fixed_filter =
  (match update_time_filter, period with
   | Some update_time_filter, _ ->
      (match Ldap_time_filter_cfg.apply update_time_filter period with
       | [] -> fixed_filter
       | filters -> `And (fixed_filter :: filters))
   | None, (None, None) -> fixed_filter
   | None, (_, _) ->
      Fmt.failwith "No update time filter provided for scope %s" scope_name)

let process
      ~commit ~period
      ~ldap_conn
      ~global_ldap_filters
      ~default_ldap_update_time_filter
      ~min_update_period
      ~scope_name ~scope_cfg ~targets
      ?csn_directory_state () =
  let attributes =
    String_set.empty
      |> List.fold (List.fold String_set.add % Target.ldap_attributes) targets
  in

  (* Combine global and scope filters *)
  let fixed_filter =
    (match global_ldap_filters, scope_cfg.ldap_filters with
     | [], [] -> failwith "No LDAP filter provided."
     | [], sfilters -> `And sfilters
     | cfilters, [] -> `And cfilters
     | cfilters, tfilters -> `And (tfilters @ cfilters))
  in
  let update_time_filter =
    (match scope_cfg.ldap_update_time_filter with
     | Some _ as fit -> fit
     | None -> default_ldap_update_time_filter)
  in

  (* Load CSN and add to filter if requested. *)
  let*? csn_state, fixed_filter =
    (match csn_directory_state with
     | None ->
        Lwt.return_ok (None, fixed_filter)
     | Some csn_directory_state ->
        let filter =
          add_time_filter ~scope_name ~update_time_filter period fixed_filter
        in
        let+? csn_state = Csn_state.load csn_directory_state filter in
        (Some csn_state, `And [Csn_state.filter csn_state; fixed_filter]))
  in

  (* Search and process entries. *)
  let rec recurse period partition_lb partition_ub =
    let filter =
      add_time_filter ~scope_name ~update_time_filter period fixed_filter
    in
    let filter =
      (match scope_cfg.ldap_partition_attribute_type with
       | None -> filter
       | Some attr_type ->
          let ge v = `Greater_or_equal (attr_type, v) in
          (match partition_lb, partition_ub with
           | None, None -> filter
           | Some lb, None -> `And [filter; ge lb]
           | None, Some ub -> `And [filter; `Not (ge ub)]
           | Some lb, Some ub -> `And [filter; ge lb; `Not (ge ub)]))
    in
    Log.info (fun f ->
      f "Scope %s %a:" scope_name pp_period period) >>= fun () ->
    Log.debug (fun f ->
      f "LDAP base: %s" scope_cfg.ldap_base_dn) >>= fun () ->
    Log.debug (fun f ->
      f "LDAP scope: %s" (Netldapx.string_of_scope scope_cfg.ldap_scope))
      >>= fun () ->
    Log.debug (fun f ->
      f "LDAP filter: %s" (Netldapx.string_of_filter filter)) >>= fun () ->
    let* lr =
      Lwt_preemptive.detach
        (Netldap.search ldap_conn
          ~base:scope_cfg.ldap_base_dn
          ~scope:scope_cfg.ldap_scope
          ~deref_aliases:`Always
          ~size_limit:(Option.get_or 0 scope_cfg.ldap_size_limit)
          ~time_limit:(Option.get_or 0 scope_cfg.ldap_time_limit)
          ~types_only:false
          ~filter
          ~attributes:(String_set.elements attributes))
        ()
    in
    let process_targets entries =
      Lwt_list.iter_p
        (fun target -> Target.process ~commit target entries)
        targets
    in
    (match lr#code with
     | `Success ->
        let+ () = process_targets lr#value in
        Ok ()
     | `TimeLimitExceeded ->
        Log.err (fun m ->
          m "Result for %s is incomplete due to time limit."
            scope_name) >>= fun () ->
        let+ () =
          if not scope_cfg.partial_is_ok then Lwt.return_unit else
          process_targets lr#partial_value
        in
        Error `Time_limit_exceeded
     | `SizeLimitExceeded ->
        (match period, scope_cfg.ldap_partition_attribute_type with
         | ((Some (tI, tzI) as tI'), (Some (tF, _) as tF')), _ when
              Ptime.Span.compare (Ptime.diff tF tI) min_update_period > 0 ->
            Log.warn (fun f ->
              f "Size limit exceeded for period %a, splitting period."
                pp_period period) >>= fun () ->
            let dtIM = Option.get @@ Ptime.Span.of_float_s @@
              0.5 *. Ptime.Span.to_float_s (Ptime.diff tF tI) in
            let tM' = Some (Ptime.add_span tI dtIM |> Option.get, tzI) in
            recurse (tI', tM') None None >>=? fun () ->
            recurse (tM', tF') None None
         | _, Some attr_type ->
            let entries = lr#partial_value in
            (match List.nth entries (Random.int (List.length entries)) with
             | `Entry (_, attrs) ->
                (match List.assoc_opt attr_type attrs with
                 | Some (partition :: _) ->
                    Log.warn (fun f ->
                      f "Size limit exceeded for period %a, splitting on %s=%s."
                        pp_period period attr_type partition) >>= fun () ->
                    recurse period partition_lb (Some partition) >>=? fun () ->
                    recurse period (Some partition) partition_ub
                 | Some [] | None ->
                    Log.err (fun f ->
                      f "Size limit exceeded and no attribute value to split on.")
                      >|= fun () ->
                    Error `Size_limit_exceeded)
             | `Reference _ -> assert false)
         | _ ->
            Log.err (fun m ->
              m "Result for %s is incomplete due to size limit." scope_name)
              >>= fun () ->
            let+ () =
              if not scope_cfg.partial_is_ok then Lwt.return_unit else
              process_targets lr#partial_value
            in
            Error `Size_limit_exceeded)
     | _ ->
        Log.err (fun m ->
          m "LDAP search for scope %s failed: %s" scope_name lr#diag_msg)
          >|= fun () ->
        Error `Search_failed)
  in
  let*? () = recurse period None None in

  (* Save the updated CSN state. *)
  (match csn_state with
   | None -> Lwt.return_ok ()
   | Some csn_state -> Csn_state.save ~commit csn_state)
