local new
new = require("device").new
local _true = require("data").new(1)
local IRUSR, IWUSR
do
  local _obj_0 = require("linux")
  IRUSR, IWUSR = _obj_0.stat.IRUSR, _obj_0.stat.IWUSR
end
local log_level
log_level = require("snihook.config").log_level
local outbox
outbox = require("mailbox").outbox
local logger = require("log")
local concat
concat = table.concat
local _whitelist = { }
local nop
nop = function() end
return function(whitelist, log_queue, log_evt)
  local log
  do
    local _with_0 = outbox(log_queue, log_evt)
    log = logger(log_level, "snihook", function(...)
      return _with_0:send(...)
    end)
  end
  local read
  read = function()
    return concat((function()
      local _accum_0 = { }
      local _len_0 = 1
      for k in pairs(_whitelist) do
        _accum_0[_len_0] = k
        _len_0 = _len_0 + 1
      end
      return _accum_0
    end)(), ",") .. "\n"
  end
  local write
  write = function(self, s)
    for action, domain in s:gmatch("(%S+)%s(%S+)") do
      if action == "add" then
        whitelist[domain] = _true
        _whitelist[domain] = _true
        log.info("Added " .. tostring(domain) .. " to whitelist")
      elseif action == "del" then
        whitelist[domain] = nil
        _whitelist[domain] = nil
        log.info("Removed " .. tostring(domain) .. " from whitelist")
      end
    end
  end
  return new({
    name = "sni_whitelist",
    mode = (IRUSR | IWUSR),
    open = nop,
    release = nop,
    read = read,
    write = write
  })
end
