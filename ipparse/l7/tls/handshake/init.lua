local subclass, Packet
do
  local _obj_0 = require("ipparse")
  subclass, Packet = _obj_0.subclass, _obj_0.Packet
end
return subclass(Packet, {
  __name = "TLSHandshake",
  record_type = 0x16,
  _get_type = function(self)
    return self:byte(0)
  end,
  _get_length = function(self)
    return self:byte(1) << 16 | self:short(2)
  end,
  data_off = 4
})
