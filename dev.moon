-- SPDX-FileCopyrightText: (c) 2024 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

:new = require"device"
:map = require"rcu"
_true = require"data".new 1
stat: {:IRUSR, :IWUSR} = require"linux"
:log_level = require"snihook.config"
logger = require"log"
:concat, :sort = table

nop = ->  -- Do nothing

(whitelist) ->
  log = logger log_level, "snihook"

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

