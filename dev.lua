local new
new = require("device").new
local _true = require("data").new(1)
local IRUSR, IWUSR
do
  local _obj_0 = require("linux")
  IRUSR, IWUSR = _obj_0.stat.IRUSR, _obj_0.stat.IWUSR
end
local set_log, notice, info, dbg
do
  local _obj_0 = require("snihook.log")
  set_log, notice, info, dbg = _obj_0.set_log, _obj_0.notice, _obj_0.info, _obj_0.dbg
end
local log_level
log_level = require("snihook.config").log_level
local nop
nop = function() end
return function(whitelist, log_queue, log_evt)
  set_log(log_queue, log_evt, log_level, "snihook")
  return new({
    name = "sni_whitelist",
    mode = (IRUSR | IWUSR),
    open = nop,
    release = nop,
    read = nop,
    write = function(self, s)
      for action, domain in s:gmatch("(%S+)%s(%S+)") do
        if action == "add" then
          whitelist[domain] = _true
          info("Added " .. tostring(domain) .. " to whitelist")
        elseif action == "del" then
          whitelist[domain] = nil
          info("Removed " .. tostring(domain) .. " from whitelist")
        end
      end
    end
  })
end
