local subclass, Packet
do
  local _obj_0 = require("ipparse")
  subclass, Packet = _obj_0.subclass, _obj_0.Packet
end
return subclass(Packet, {
  __name = "UDP",
  protocol_type = 0x11,
  _get_sport = function(self)
    return self:short(0)
  end,
  _get_dport = function(self)
    return self:short(2)
  end,
  _get_length = function(self)
    return self:short(4)
  end,
  _get_checksum = function(self)
    return self:short(6)
  end,
  data_off = 8
})
