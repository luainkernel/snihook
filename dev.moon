-- SPDX-FileCopyrightText: (c) 2024 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

:new = require"device"
:map = require"rcu"
_true = require"data".new 1
{:IRUSR, :IWUSR} = require"linux.stat"
cfg = require"snihook.config"
logger = require"snihook.log"
:concat, :sort = table

nop = ->  -- Do nothing

(whitelist) ->
  log = logger cfg.log_level, "snihook", rate_limit_window: cfg.log_rate_limit_window, rate_limit_burst: cfg.log_rate_limit_burst

  read = ->
    lst = {}
    map whitelist, => lst[#lst+1] = @
    sort lst
    concat(lst, ",") .. "\n"
  write = (s) =>
    for action, domain in s\gmatch"(%S+)%s(%S+)"
      if action == "+"
        whitelist[domain] = _true
        log.info"Added #{domain} to whitelist"
      elseif action == "-"
        whitelist[domain] = nil
        log.info"Removed #{domain} from whitelist"
  new name: "sni_whitelist", mode: (IRUSR | IWUSR), open: nop, release: nop, :read, :write
