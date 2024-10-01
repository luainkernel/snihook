local concat
concat = table.concat
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
local logger
logger = function(self, lvl, txt)
  if txt == nil then
    txt = levels[lvl + 1]
  end
  return function(...)
    if not (self.level < lvl) then
      return self.log(tostring(self.msg) .. " " .. tostring(txt) .. ": " .. concat((function(...)
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
return function(level, msg, log)
  if msg == nil then
    msg = ""
  end
  if log == nil then
    log = print
  end
  local self = {
    log = log,
    msg = msg,
    level = tonumber(level) or levels[level]
  }
  for i, lvl in ipairs(levels) do
    self[lvl:lower()] = logger(self, i - 1)
  end
  return self
end
