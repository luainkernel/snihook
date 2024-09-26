local concat
concat = table.concat
local outbox
outbox = require("mailbox").outbox
local levels = {
  "EMERGENCY",
  "ALERT",
  "CRITICAL",
  "ERROR",
  "WARNING",
  "NOTICE",
  "INFO",
  "DEBUG"
}
for i = 1, #levels do
  levels[levels[i]] = i - 1
end
local self = { }
self.set_log = function(queue, evt, lvl, msg)
  if msg == nil then
    msg = ""
  end
  self.msg = msg
  self.level = tonumber(lvl) or levels[lvl]
  self.log = outbox(queue, evt)
end
local logger
logger = function(lvl, txt)
  if txt == nil then
    txt = levels[lvl + 1]
  end
  return function(...)
    if not (self.level < lvl) then
      return self.log:send(tostring(self.msg) .. " " .. tostring(txt) .. ": " .. concat((function(...)
        local _accum_0 = { }
        local _len_0 = 1
        local _list_0 = {
          ...
        }
        for _index_0 = 1, #_list_0 do
          local part = _list_0[_index_0]
          _accum_0[_len_0] = tostring(part)
          _len_0 = _len_0 + 1
        end
        return _accum_0
      end)(...), "\t"))
    end
  end
end
self.emergency = logger(0)
self.alert = logger(1)
self.critical = logger(2)
self.error = logger(3)
self.warn = logger(4)
self.notice = logger(5)
self.info = logger(6)
self.dbg = logger(7)
self.logger = logger
return self
