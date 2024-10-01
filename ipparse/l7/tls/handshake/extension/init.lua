local subclass, Packet
do
  local _obj_0 = require("ipparse")
  subclass, Packet = _obj_0.subclass, _obj_0.Packet
end
return subclass(Packet, {
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
