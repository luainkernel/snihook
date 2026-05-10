import concat from table
:time = require"linux"

levels = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"}
levels[levels[i]] = i-1 for i = 1, #levels

sanitize = (part) ->
  s = "#{part}"
  -- Keep kernel logs text-only: replace non-printable bytes.
  if s\find "[%z\1-\8\11\12\14-\31\127-\255]"
    s\gsub("[^ -~\t]", ".")
  else
    s


prune_rate_state = (state, now, window) ->
  return unless state and next(state)
  for k, v in pairs state
    if (now - v.t0) >= (window * 10)
      state[k] = nil


can_log = (self, lvl, line) ->
  rl = self.rate_limit
  return true unless rl
  now = time! / 1000000000
  key = "#{lvl}\0#{line}"
  ent = rl.state[key]
  unless ent
    rl.state[key] = {t0: now, n: 1}
    if rl.size > 2048
      prune_rate_state rl.state, now, rl.window
      rl.size = 0
      for _ in pairs rl.state
        rl.size += 1
    else
      rl.size += 1
    return true
  if (now - ent.t0) >= rl.window
    ent.t0 = now
    ent.n = 1
    return true
  if ent.n < rl.burst
    ent.n += 1
    return true
  false

logger = (lvl, txt=levels[lvl+1]) =>
  (...) ->
    unless @level < lvl
      line = concat [ sanitize(part) for part in *{...} ], "\t"
      return unless can_log @, lvl, line
      @.log "#{@msg} #{txt}: #{line}"

(level, msg="", log=print, opts=nil) ->
  if type(log) == "table" and not opts
    opts = log
    log = print

  opts or= {}
  window = tonumber(opts.rate_limit_window) or 2
  burst = tonumber(opts.rate_limit_burst) or 1
  rate_limit = nil
  if window > 0 and burst > 0
    rate_limit = window: window, burst: burst, state: {}, size: 0

  @ = :log, :msg, :rate_limit, level: tonumber(level) or levels[level]
  @[lvl\lower!] = logger(@, i-1) for i, lvl in ipairs levels
  @
