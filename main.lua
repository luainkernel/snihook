local rcu = require("rcu")
local run, spawn, stop
do
  local _obj_0 = rcu and require("lunatik.runner")
  run, spawn, stop = _obj_0.run, _obj_0.spawn, _obj_0.stop
end
local shouldstop
shouldstop = require("thread").shouldstop
local schedule
schedule = require("linux").schedule
local mailbox = require("mailbox")
local lunatik = require("lunatik")
local cfg = require("snihook.config")
return function()
  local whitelist = rcu.table()
  local quic_verdicts = rcu.table()
  local quic_mailbox = mailbox.inbox(cfg.quic_mailbox_size or 262144)
  local env = lunatik._ENV
  env.snihook_quic_queue = quic_mailbox.queue
  env.snihook_quic_event = quic_mailbox.event
  env.snihook_quic_whitelist = whitelist
  env.snihook_quic_verdicts = quic_verdicts
  local dev_rt = run("snihook/dev")
  local hook_rt = run("snihook/hook", "softirq")
  spawn("snihook/quic", "process")
  dev_rt:resume(whitelist)
  hook_rt:resume(whitelist, quic_mailbox.queue, quic_mailbox.event, quic_verdicts)
  while not shouldstop() do
    schedule(1000)
  end
  stop("snihook/quic")
  stop("snihook/hook")
  stop("snihook/dev")
  env.snihook_quic_queue = nil
  env.snihook_quic_event = nil
  env.snihook_quic_whitelist = nil
  env.snihook_quic_verdicts = nil
end
