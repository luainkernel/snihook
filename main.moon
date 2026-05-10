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
:run, :spawn, :stop = rcu and require"lunatik.runner"
:shouldstop = require"thread"
:schedule = require"linux"
mailbox = require"mailbox"
lunatik = require"lunatik"
cfg = require"snihook.config"


->
  whitelist = rcu.table!
  quic_verdicts = rcu.table!
  quic_mailbox = mailbox.inbox cfg.quic_mailbox_size or 262144
  env = lunatik._ENV
  env.snihook_quic_queue = quic_mailbox.queue
  env.snihook_quic_event = quic_mailbox.event
  env.snihook_quic_whitelist = whitelist
  env.snihook_quic_verdicts = quic_verdicts

  dev_rt = run "snihook/dev"
  hook_rt = run "snihook/hook", "softirq"
  spawn "snihook/quic", "process"
  dev_rt\resume whitelist
  hook_rt\resume whitelist, quic_mailbox.queue, quic_mailbox.event, quic_verdicts


  while not shouldstop! do schedule 1000

  stop "snihook/quic"
  stop "snihook/hook"
  stop "snihook/dev"
  env.snihook_quic_queue = nil
  env.snihook_quic_event = nil
  env.snihook_quic_whitelist = nil
  env.snihook_quic_verdicts = nil
