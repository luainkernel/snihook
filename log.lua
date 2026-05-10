local concat
concat = table.concat
local time
time = require("linux").time
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
local sanitize
sanitize = function(part)
  local s = tostring(part)
  if s:find("[%z\1-\8\11\12\14-\31\127-\255]") then
    return s:gsub("[^ -~\t]", ".")
  else
    return s
  end
end
local prune_rate_state
prune_rate_state = function(state, now, window)
  if not (state and next(state)) then
    return 
  end
  for k, v in pairs(state) do
    if (now - v.t0) >= (window * 10) then
      state[k] = nil
    end
  end
end
local can_log
can_log = function(self, lvl, line)
  local rl = self.rate_limit
  if not (rl) then
    return true
  end
  local now = time() / 1000000000
  local key = tostring(lvl) .. "\0" .. tostring(line)
  local ent = rl.state[key]
  if not (ent) then
    rl.state[key] = {
      t0 = now,
      n = 1
    }
    if rl.size > 2048 then
      prune_rate_state(rl.state, now, rl.window)
      rl.size = 0
      for _ in pairs(rl.state) do
        rl.size = rl.size + 1
      end
    else
      rl.size = rl.size + 1
    end
    return true
  end
  if (now - ent.t0) >= rl.window then
    ent.t0 = now
    ent.n = 1
    return true
  end
  if ent.n < rl.burst then
    ent.n = ent.n + 1
    return true
  end
  return false
end
local logger
logger = function(self, lvl, txt)
  if txt == nil then
    txt = levels[lvl + 1]
  end
  return function(...)
    if not (self.level < lvl) then
      local line = concat((function(...)
        local _accum_0 = { }
        local _len_0 = 1
        local _list_0 = {
          ...
        }
        for _index_0 = 1, #_list_0 do
          local part = _list_0[_index_0]
          _accum_0[_len_0] = sanitize(part)
          _len_0 = _len_0 + 1
        end
        return _accum_0
      end)(...), "\t")
      if not (can_log(self, lvl, line)) then
        return 
      end
      return self.log(tostring(self.msg) .. " " .. tostring(txt) .. ": " .. tostring(line))
    end
  end
end
return function(level, msg, log, opts)
  if msg == nil then
    msg = ""
  end
  if log == nil then
    log = print
  end
  if opts == nil then
    opts = nil
  end
  if type(log) == "table" and not opts then
    opts = log
    log = print
  end
  opts = opts or { }
  local window = tonumber(opts.rate_limit_window) or 2
  local burst = tonumber(opts.rate_limit_burst) or 1
  local rate_limit = nil
  if window > 0 and burst > 0 then
    rate_limit = {
      window = window,
      burst = burst,
      state = { },
      size = 0
    }
  end
  local self = {
    log = log,
    msg = msg,
    rate_limit = rate_limit,
    level = tonumber(level) or levels[level]
  }
  for i, lvl in ipairs(levels) do
    self[lvl:lower()] = logger(self, i - 1)
  end
  return self
end
