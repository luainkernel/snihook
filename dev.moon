-- SPDX-FileCopyrightText: (c) 2024 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

:new = require"device"
_true = require"data".new 1
stat: {:IRUSR, :IWUSR} = require"linux"
:set_log, :notice, :info, :dbg = require"snihook.log"
:log_level = require"snihook.config"

nop = ->  -- Do nothing

(whitelist, log_queue, log_evt) ->
  set_log log_queue, log_evt, log_level, "snihook"

  new name: "sni_whitelist", mode: (IRUSR | IWUSR), open: nop, release: nop, read: nop, write: (s) =>
    for action, domain in s\gmatch"(%S+)%s(%S+)"
      if action == "add"
        whitelist[domain] = _true
        info"Added #{domain} to whitelist"
      elseif action == "del"
        whitelist[domain] = nil
        info"Removed #{domain} from whitelist"
