import concat from table

levels = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"}
levels[levels[i]] = i-1 for i = 1, #levels

logger = (lvl, txt=levels[lvl+1]) =>
  (...) ->
    unless @level < lvl
      @.log "#{@msg} #{txt}: " .. concat [ "#{part}" for part in *{...} ], "\t"

(level, msg="", log=print) ->
  @ = :log, :msg, level: tonumber(level) or levels[level]
  @[lvl\lower!] = logger(@, i-1) for i, lvl in ipairs levels
  @
