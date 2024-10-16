-- SPDX-FileCopyrightText: (c) 2024 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

-- Filter TLS packets based on SNI

-- Assuming that MoonScript files are transpiled into in /lib/modules/lua/snihook/*.lua,
--
-- > sudo lunatik spawn snihook/main

-- To disable it:
--
-- > sudo lunatik stop snihook/main

-- Once enabled, to add entries to whitelist:
-- > echo "+ DOMAIN" > /dev/sni_whitelist
-- To remove entries:
-- > echo "- DOMAIN" > /dev/sni_whitelist


rcu = require"rcu"
:run = rcu and require"lunatik.runner"
:shouldstop = require"thread"
:schedule = require"linux"


->
  whitelist = rcu.table!

  runtimes = {
    run "snihook/dev",  true
    run "snihook/hook", false
  }
  rt\resume whitelist for rt in *runtimes


  while not shouldstop! do schedule 1000

  rt\stop! for rt in *runtimes

