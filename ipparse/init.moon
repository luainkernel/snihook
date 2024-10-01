if path = (...)\match"(.*)%.[^%.]-"  -- Add subdirectory to package.path if applicable
  path = package.path\match"^[^%?]+" .. path
  package.path ..= ";"..path.."/?.lua;"..path.."/?/init.lua"

:ntoh16, :ntoh32 = require"linux"
log = require"log" "NOTICE", "ipparse"


Object = {
  __name: "Object"
  new: (obj) =>
    cls = @ ~= obj and @ or nil
    setmetatable obj, {
      __index: (k) =>
        if getter = rawget(@, "_get_#{k}") or cls and cls["_get_#{k}"]
          @[k] = getter @
          @[k]
        elseif cls
          cls[k]
      __call: (...) => obj\new ...
    }
}
Object.new Object, Object
subclass = Object.new


Packet = subclass Object, {
  __name: "Packet"
  new: (obj) =>
    assert obj.skb, "I need a skb to parse"
    obj.off or= 0
    Object.new @, obj

  bit: (offset, n = 1) =>
    if log.level == 7
      ok, ret = pcall @skb.getbyte, @skb, @off+offset
      ((ret >> (8-n)) & 1) if ok else log.error @__name, "bit", ret, "#{@off} #{offset} #{#@skb}"
    else
      (@skb\getbyte(@off+offset) >> n) & 1

  nibble: (offset, half = 1) =>
    if log.level == 7
      ok, ret = pcall @skb.getbyte, @skb, @off+offset
      (half == 1 and ret >> 4 or ret & 0xf) if ok else log.error @__name, "nibble", "#{@off} #{offset} #{#@skb}"
    else
      b = @skb\getbyte @off+offset
      half == 1 and b >> 4 or b & 0xf

  byte: (offset) =>
    if log.level == 7
      ok, ret = pcall @skb.getbyte, @skb, @off+offset
      ret if ok else log.error @__name, "byte", ret, "#{@off} #{offset} #{#@skb}"
    else
      @skb\getbyte @off+offset

  short: (offset) =>
    if log.level == 7
      ok, ret = pcall @skb.getuint16, @skb, @off+offset
      ntoh16(ret) if ok else log.error @__name, "short", ret, "#{@off} #{offset} #{#@skb}"
    else
      ntoh16 @skb\getuint16 @off+offset

  word: (offset) =>
    if log.level == 7
      ok, ret = pcall @skb.getuint32, @skb, @off+offset
      ntoh32(ret) if ok else log.error @__name, "word", ret, "#{@off} #{offset} #{#@skb}"
    else
      ntoh32 @skb\getuint32 @off+offset

  str: (offset=0, length=#@skb-@off) =>
    off = @off + offset
    frag = ""
    if off + length > #@skb
      length = #@skb - off
      log.warn"Incomplete data. Fragmented packet?."
    if log.level == 7
      ok, ret = pcall @skb.getstring, @skb, @off+offset, length
      (ret .. frag) if ok else log.error @__name, "str", ret, "#{@off} #{offset} #{length} #{#@skb}"
    else
      @skb\getstring(@off+offset, length) .. frag

  is_empty: => @off >= #@skb

  _get_data: => skb: @skb, off: @off + @data_off
}

{
  :log,
  :Object, :subclass, :Packet
}
