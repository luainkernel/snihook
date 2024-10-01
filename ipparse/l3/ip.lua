local subclass, Packet
do
  local _obj_0 = require("ipparse")
  subclass, Packet = _obj_0.subclass, _obj_0.Packet
end
local _ = [[protocols: {
    TCP:    0x06
    UDP:    0x11
    GRE:    0x2F
    ESP:    0x32
    ICMPv6: 0x3A
    OSPF:   0x59
  }
]]
return subclass(Packet, {
  __name = "IP",
  _get_version = function(self)
    return self:nibble(0)
  end
})
