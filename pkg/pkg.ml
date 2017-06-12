#use "topfind"
#require "topkg-jbuilder"
open Topkg

let licenses = [Pkg.std_file "COPYING"]
let () = Topkg_jbuilder.describe ~licenses ~name:"subsocia-sync-ldap" ()
