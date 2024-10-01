local subclass
subclass = require("ipparse").subclass
local IP = require("ipparse.l3.ip")
local concat
concat = table.concat
return subclass(IP, {
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
