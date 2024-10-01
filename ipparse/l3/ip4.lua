local subclass
subclass = require("ipparse").subclass
local IP = require("ipparse.l3.ip")
local concat
concat = table.concat
return subclass(IP, {
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
