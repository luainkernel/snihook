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
-- > echo add DOMAIN > /dev/sni_whitelist
-- To remove entries:
-- > echo del DOMAIN > /dev/sni_whitelist


rcu = require"rcu"
:run = require"rcu" and require"lunatik.runner"
:shouldstop = require"thread"
:inbox = require"mailbox"
:schedule, :time = require"linux"


->
  whitelist = rcu.table!
  log = inbox 100 * 1024

  runtimes = {
    run("snihook/dev", true),
    run("snihook/hook", false)
  }
  rt\resume whitelist, log.queue, log.event for rt in *runtimes

  previous = __mode: "kv"
  while not shouldstop!
    if event = log\receive!
      t = time! / 1000000000
      if _t = previous[event]
        previous[event] = nil if t - _t >= 10
      else
        print event
        previous[event] = t
    else
      schedule 1000

  rt\stop! for rt in *runtimes

