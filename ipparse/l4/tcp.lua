local subclass, Packet
do
  local _obj_0 = require("ipparse")
  subclass, Packet = _obj_0.subclass, _obj_0.Packet
end
return subclass(Packet, {
  __name = "TCP",
  protocol_type = 0x06,
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
