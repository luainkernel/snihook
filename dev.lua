local new
new = require("device").new
local map
map = require("rcu").map
local _true = require("data").new(1)
local IRUSR, IWUSR
do
  local _obj_0 = require("linux")
  IRUSR, IWUSR = _obj_0.stat.IRUSR, _obj_0.stat.IWUSR
end
local log_level
log_level = require("snihook.config").log_level
local logger = require("log")
local concat, sort
do
  local _obj_0 = table
  concat, sort = _obj_0.concat, _obj_0.sort
end
local nop
nop = function() end
return function(whitelist)
  local log = logger(log_level, "snihook")
  local read
  read = function()
    local lst = { }
    map(whitelist, function(self)
      lst[#lst + 1] = self
    end)
    sort(lst)
    return concat(lst, ",") .. "\n"
  end
  local write
  write = function(self, s)
    for action, domain in s:gmatch("(%S+)%s(%S+)") do
      if action == "+" then
        whitelist[domain] = _true
        log.info("Added " .. tostring(domain) .. " to whitelist")
      elseif action == "-" then
        whitelist[domain] = nil
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
