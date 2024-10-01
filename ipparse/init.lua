do
  local path = (...):match("(.*)%.[^%.]-")
  if path then
    path = package.path:match("^[^%?]+") .. path
    package.path = package.path .. (";" .. path .. "/?.lua;" .. path .. "/?/init.lua")
  end
end
local ntoh16, ntoh32
do
  local _obj_0 = require("linux")
  ntoh16, ntoh32 = _obj_0.ntoh16, _obj_0.ntoh32
end
local log = require("log")("NOTICE", "ipparse")
local Object = {
  __name = "Object",
  new = function(self, obj)
    local cls = self ~= obj and self or nil
    return setmetatable(obj, {
      __index = function(self, k)
        do
          local getter = rawget(self, "_get_" .. tostring(k)) or cls and cls["_get_" .. tostring(k)]
          if getter then
            self[k] = getter(self)
            return self[k]
          elseif cls then
            return cls[k]
          end
        end
      end,
      __call = function(self, ...)
        return obj:new(...)
      end
    })
  end
}
Object.new(Object, Object)
local subclass = Object.new
local Packet = subclass(Object, {
  __name = "Packet",
  new = function(self, obj)
    assert(obj.skb, "I need a skb to parse")
    obj.off = obj.off or 0
    return Object.new(self, obj)
  end,
  bit = function(self, offset, n)
    if n == nil then
      n = 1
    end
    if log.level == 7 then
      local ok, ret = pcall(self.skb.getbyte, self.skb, self.off + offset)
      if ok then
        return ((ret >> (8 - n)) & 1)
      else
        return log.error(self.__name, "bit", ret, tostring(self.off) .. " " .. tostring(offset) .. " " .. tostring(#self.skb))
      end
    else
      return (self.skb:getbyte(self.off + offset) >> n) & 1
    end
  end,
  nibble = function(self, offset, half)
    if half == nil then
      half = 1
    end
    if log.level == 7 then
      local ok, ret = pcall(self.skb.getbyte, self.skb, self.off + offset)
      if ok then
        return (half == 1 and ret >> 4 or ret & 0xf)
      else
        return log.error(self.__name, "nibble", tostring(self.off) .. " " .. tostring(offset) .. " " .. tostring(#self.skb))
      end
    else
      local b = self.skb:getbyte(self.off + offset)
      return half == 1 and b >> 4 or b & 0xf
    end
  end,
  byte = function(self, offset)
    if log.level == 7 then
      local ok, ret = pcall(self.skb.getbyte, self.skb, self.off + offset)
      if ok then
        return ret
      else
        return log.error(self.__name, "byte", ret, tostring(self.off) .. " " .. tostring(offset) .. " " .. tostring(#self.skb))
      end
    else
      return self.skb:getbyte(self.off + offset)
    end
  end,
  short = function(self, offset)
    if log.level == 7 then
      local ok, ret = pcall(self.skb.getuint16, self.skb, self.off + offset)
      if ok then
        return ntoh16(ret)
      else
        return log.error(self.__name, "short", ret, tostring(self.off) .. " " .. tostring(offset) .. " " .. tostring(#self.skb))
      end
    else
      return ntoh16(self.skb:getuint16(self.off + offset))
    end
  end,
  word = function(self, offset)
    if log.level == 7 then
      local ok, ret = pcall(self.skb.getuint32, self.skb, self.off + offset)
      if ok then
        return ntoh32(ret)
      else
        return log.error(self.__name, "word", ret, tostring(self.off) .. " " .. tostring(offset) .. " " .. tostring(#self.skb))
      end
    else
      return ntoh32(self.skb:getuint32(self.off + offset))
    end
  end,
  str = function(self, offset, length)
    if offset == nil then
      offset = 0
    end
    if length == nil then
      length = #self.skb - self.off
    end
    local off = self.off + offset
    local frag = ""
    if off + length > #self.skb then
      length = #self.skb - off
      log.warn("Incomplete data. Fragmented packet?.")
    end
    if log.level == 7 then
      local ok, ret = pcall(self.skb.getstring, self.skb, self.off + offset, length)
      if ok then
        return (ret .. frag)
      else
        return log.error(self.__name, "str", ret, tostring(self.off) .. " " .. tostring(offset) .. " " .. tostring(length) .. " " .. tostring(#self.skb))
      end
    else
      return self.skb:getstring(self.off + offset, length) .. frag
    end
  end,
  is_empty = function(self)
    return self.off >= #self.skb
  end,
  _get_data = function(self)
    return {
      skb = self.skb,
      off = self.off + self.data_off
    }
  end
})
return {
  log = log,
  Object = Object,
  subclass = subclass,
  Packet = Packet
}
