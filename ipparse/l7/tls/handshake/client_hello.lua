local subclass, Packet
do
  local _obj_0 = require("ipparse")
  subclass, Packet = _obj_0.subclass, _obj_0.Packet
end
local TLSExtension = require("ipparse.l7.tls.handshake.extension")
local min
min = math.min
local wrap, yield
do
  local _obj_0 = coroutine
  wrap, yield = _obj_0.wrap, _obj_0.yield
end
local TLS_extensions = setmetatable({
  [0x00] = require("ipparse.l7.tls.handshake.extension.server_name")
}, {
  __index = function(self, k)
    return subclass(TLSExtension, {
      __name = "UnknownTlsExtension",
      type_str = function(self)
        return "unknown"
      end
    })
  end
})
return subclass(Packet, {
  __name = "TLSClientHello",
  message_type = 0x01,
  _get_client_version = function(self)
    return tostring(self:byte(0)) .. "." .. tostring(self:byte(1))
  end,
  _get_client_random = function(self)
    return self:str(2, 32)
  end,
  _get_session_id_length = function(self)
    return self:byte(34)
  end,
  _get_session_id = function(self)
    return self:str(35, self.session_id_length)
  end,
  _get_ciphers_offset = function(self)
    return 35 + self.session_id_length
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
  end
})
