import concat from table
import outbox from require"mailbox"

levels = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"}
levels[levels[i]] = i-1 for i = 1, #levels

@ = {}

@set_log = (queue, evt, lvl, @msg="") ->
  @level = tonumber(lvl) or levels[lvl]
  @log = outbox queue, evt

logger = (lvl, txt=levels[lvl+1]) ->
  (...) ->
    unless @level < lvl
      @log\send "#{@msg} #{txt}: " .. concat [ "#{part}" for part in *{...} ], "\t"

@emergency = logger 0
@alert = logger 1
@critical = logger 2
@error = logger 3
@warn = logger 4
@notice = logger 5
@info = logger 6
@dbg = logger 7
@logger = logger
@

