-- SPDX-FileCopyrightText: (c) 2024 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

:new = require"device"
_true = require"data".new 1
stat: {:IRUSR, :IWUSR} = require"linux"
:log_level = require"snihook.config"
:outbox = require"mailbox"
logger = require"log"
:concat = table
_whitelist = {}

nop = ->  -- Do nothing

(whitelist, log_queue, log_evt) ->
  local log
  with outbox log_queue, log_evt
    log = logger log_level, "snihook", (...) -> \send ...

  read = -> concat([k for k in pairs _whitelist], ",") .. "\n"
  write = (s) =>
    for action, domain in s\gmatch"(%S+)%s(%S+)"
      if action == "add"
        whitelist[domain] = _true
        _whitelist[domain] = _true
        log.info"Added #{domain} to whitelist"
      elseif action == "del"
        whitelist[domain] = nil
        _whitelist[domain] = nil
        log.info"Removed #{domain} from whitelist"
  new name: "sni_whitelist", mode: (IRUSR | IWUSR), open: nop, release: nop, :read, :write
