local concat, insert
do
  local _obj_0 = table
  concat, insert = _obj_0.concat, _obj_0.insert
end
local min
min = math.min
local wrap, yield
do
  local _obj_0 = coroutine
  wrap, yield = _obj_0.wrap, _obj_0.yield
end
local ntoh16, ntoh32
do
  local _obj_0 = require("linux")
  ntoh16, ntoh32 = _obj_0.ntoh16, _obj_0.ntoh32
end
local log = require("snihook.log")
local data_new
data_new = require("data").new
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
local IP = subclass(Packet, {
  __name = "IP",
  _get_version = function(self)
    return self:nibble(0)
  end,
  protocols = {
    TCP = 0x06,
    UDP = 0x11,
    GRE = 0x2F,
    ESP = 0x32,
    ICMPv6 = 0x3A,
    OSPF = 0x59
  }
})
local IP4 = subclass(IP, {
  __name = "IP4",
  get_ip_at = function(self, off)
    return concat((function()
      local _accum_0 = { }
      local _len_0 = 1
      for i = off, off + 3 do
        _accum_0[_len_0] = ("%d"):format(self:byte(i))
        _len_0 = _len_0 + 1
      end
      return _accum_0
    end)(), ".")
  end,
  is_fragment = function(self)
    return self.mf ~= 0 or self.fragmentation_off ~= 0
  end,
  _get_ihl = function(self)
    return self:nibble(0, 2)
  end,
  _get_tos = function(self)
    return self:byte(1)
  end,
  _get_length = function(self)
    return self:short(2)
  end,
  _get_id = function(self)
    return self:short(4)
  end,
  _get_reserved = function(self)
    return self:bit(6, 1)
  end,
  _get_df = function(self)
    return self:bit(6, 2)
  end,
  _get_mf = function(self)
    return self:bit(6, 3)
  end,
  _get_fragmentation_off = function(self)
    return (self:bit(6, 4) << 12) | (self:nibble(6, 2) << 8) | self:byte(7)
  end,
  _get_ttl = function(self)
    return self:byte(8)
  end,
  _get_protocol = function(self)
    return self:byte(9)
  end,
  _get_header_checksum = function(self)
    return self:short(10)
  end,
  _get_src = function(self)
    return self:get_ip_at(12)
  end,
  _get_dst = function(self)
    return self:get_ip_at(16)
  end,
  _get_data_off = function(self)
    return 4 * self.ihl
  end,
  _get_data_len = function(self)
    return self.length - self.data_off
  end
})
local IP6 = subclass(IP, {
  __name = "IP6",
  get_ip_at = function(self, off)
    return concat((function()
      local _accum_0 = { }
      local _len_0 = 1
      for i = off, off + 14, 2 do
        _accum_0[_len_0] = ("%x"):format(self:short(i))
        _len_0 = _len_0 + 1
      end
      return _accum_0
    end)(), ":")
  end,
  is_fragment = function(self)
    return false
  end,
  _get_length = function(self)
    return self.data_off + self:short(4)
  end,
  _get_next_header = function(self)
    return self:byte(6)
  end,
  _get_protocol = function(self)
    return self.next_header
  end,
  _get_src = function(self)
    return self:get_ip_at(8)
  end,
  _get_dst = function(self)
    return self:get_ip_at(24)
  end,
  _get_data_off = function(self)
    return 40
  end
})
local Fragmented_IP4 = subclass(IP4, {
  new = function(self, obj)
    if obj == nil then
      obj = { }
    end
    obj.off = obj.off or 0
    return Object.new(self, obj)
  end,
  insert = function(self, fragment)
    do
      local prec = self[1]
      if prec then
        assert(fragment.id == prec.id)
        for i = 1, #self do
          if fragment.fragmentation_off < self[i].fragmentation_off then
            insert(self, i, fragment)
            return self
          end
        end
        self[#self + 1] = fragment
        return self
      end
    end
    self[1] = fragment
    return self
  end,
  is_complete = function(self)
    if self[#self].mf ~= 0 then
      return false
    end
    for i = 2, #self do
      local this, prec = self[i], self[i - 1]
      if (this.fragmentation_off << 3) ~= (prec.fragmentation_off << 3) + prec.data_len then
        return false
      end
    end
    return true
  end,
  _get_skb = function(self)
    assert(self:is_complete(), "Can't access payload of incomplete fragmented packet")
    local fragmentation_off, data_len
    do
      local _obj_0 = self[#self]
      fragmentation_off, data_len = _obj_0.fragmentation_off, _obj_0.data_len
    end
    local skb = data_new((fragmentation_off << 3) + data_len)
    local off = 0
    local _skb
    _skb = self[1].skb
    for j = 0, #_skb - 1 do
      skb:setbyte(off, _skb:getbyte(j))
      off = off + 1
    end
    for i = 2, #self do
      local data_off
      do
        local _obj_0 = self[i]
        _skb, data_off = _obj_0.skb, _obj_0.data_off
      end
      for j = 0, #_skb - 1 do
        skb:setbyte(off, _skb:getbyte(data_off + j))
        off = off + 1
      end
    end
    return skb
  end
})
local auto_ip
auto_ip = function(self)
  local ip = IP({
    skb = self
  })
  local _exp_0 = ip.version
  if 4 == _exp_0 then
    return IP4({
      skb = self
    })
  elseif 6 == _exp_0 then
    return IP6({
      skb = self
    })
  end
end
local TCP = subclass(Packet, {
  __name = "TCP",
  _get_sport = function(self)
    return self:short(0)
  end,
  _get_dport = function(self)
    return self:short(2)
  end,
  _get_sequence_number = function(self)
    return self:word(4)
  end,
  _get_acknowledgment_number = function(self)
    return self:word(8)
  end,
  _get_data_off = function(self)
    return 4 * self:nibble(12)
  end,
  _get_URG = function(self)
    return self:bit(13, 3)
  end,
  _get_ACK = function(self)
    return self:bit(13, 4)
  end,
  _get_PSH = function(self)
    return self:bit(13, 5)
  end,
  _get_RST = function(self)
    return self:bit(13, 6)
  end,
  _get_SYN = function(self)
    return self:bit(13, 7)
  end,
  _get_FIN = function(self)
    return self:bit(13, 8)
  end,
  _get_window = function(self)
    return self:short(14)
  end,
  _get_checksum = function(self)
    return self:short(16)
  end,
  _get_urgent_pointer = function(self)
    return self:short(18)
  end
})
local TLS = subclass(Packet, {
  __name = "TLS",
  _get_type = function(self)
    return self:byte(0)
  end,
  _get_version = function(self)
    return tostring(self:byte(1)) .. "." .. tostring(self:byte(2))
  end,
  _get_length = function(self)
    return self:short(3)
  end,
  _get_data_off = function(self)
    return 5
  end,
  types = {
    handshake = 0x16
  }
})
local TLSExtension = subclass(Packet, {
  __name = "TLSExtension",
  _get_type = function(self)
    return self:short(0)
  end,
  _get_length = function(self)
    return 4 + self:short(2)
  end,
  types = {
    server_name = 0x00
  }
})
local TLS_extensions = setmetatable({
  [0x00] = subclass(TLSExtension, {
    __name = "ServerNameIndication",
    _get_type_str = function(self)
      return "server name"
    end,
    _get_server_name = function(self)
      return self:str(9, self:short(7))
    end
  })
}, {
  __index = function(self, k)
    return subclass(TLSExtension, {
      __name = "UnknownTlsExtension",
      _get_type_str = function(self)
        return "unknown"
      end
    })
  end
})
local TLSHandshake = subclass(Packet, {
  __name = "TLSHandshake",
  _get_type = function(self)
    return self:byte(0)
  end,
  _get_length = function(self)
    return self:byte(1) << 16 | self:short(2)
  end,
  _get_client_version = function(self)
    return tostring(self:byte(4)) .. "." .. tostring(self:byte(5))
  end,
  _get_client_random = function(self)
    return self:str(6, 32)
  end,
  _get_session_id_length = function(self)
    return self:byte(38)
  end,
  _get_session_id = function(self)
    return self:str(39, self.session_id_length)
  end,
  _get_ciphers_offset = function(self)
    return 39 + self.session_id_length
  end,
  _get_ciphers_length = function(self)
    return self:short(self.ciphers_offset)
  end,
  _get_ciphers = function(self)
    local _accum_0 = { }
    local _len_0 = 1
    for i = 0, self.ciphers_length - 2, 2 do
      _accum_0[_len_0] = self:short(self.ciphers_offset + 2 + i)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end,
  _get_compressions_offset = function(self)
    return self.ciphers_offset + 2 + self.ciphers_length
  end,
  _get_compressions_length = function(self)
    return self:byte(self.compressions_offset)
  end,
  _get_compressions = function(self)
    local _accum_0 = { }
    local _len_0 = 1
    for i = 0, self.compressions_length - 1 do
      _accum_0[_len_0] = self:byte(self.compressions_offset + 1 + i)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end,
  _get_extensions_offset = function(self)
    return self.compressions_offset + 1 + self.compressions_length
  end,
  _get_extensions = function(self)
    local _accum_0 = { }
    local _len_0 = 1
    for extension in self:iter_extensions() do
      _accum_0[_len_0] = extension
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end,
  iter_extensions = function(self)
    return wrap(function()
      local offset = self.extensions_offset + 2
      local max_offset = min(#self.skb - self.off - 6, offset + self:short(self.extensions_offset))
      while offset < max_offset do
        local extension = TLS_extensions[self:short(offset)]({
          skb = self.skb,
          off = self.off + offset
        })
        yield(extension)
        offset = offset + extension.length
      end
    end)
  end,
  types = {
    hello = 0x01
  }
})
return {
  log = log,
  Object = Object,
  subclass = subclass,
  Packet = Packet,
  IP = IP,
  IP4 = IP4,
  Fragmented_IP4 = Fragmented_IP4,
  IP6 = IP6,
  auto_ip = auto_ip,
  TCP = TCP,
  TLS = TLS,
  TLSExtension = TLSExtension,
  TLSHandshake = TLSHandshake,
  TLS_extensions = TLS_extensions
}
