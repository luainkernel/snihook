local subclass, Packet
do
  local _obj_0 = require("ipparse")
  subclass, Packet = _obj_0.subclass, _obj_0.Packet
end
return subclass(Packet, {
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
  data_off = 5
})
