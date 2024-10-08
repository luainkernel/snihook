local subclass, Packet
do
  local _obj_0 = require("ipparse")
  subclass, Packet = _obj_0.subclass, _obj_0.Packet
end
local concat, unpack
do
  local _obj_0 = table
  concat, unpack = _obj_0.concat, _obj_0.unpack
end
return subclass(Packet, {
  __name = "DNSQuestion",
  _get_labels_offsets = function(self)
    local offsets = { }
    local pos = 0
    for i = 1, 1000 do
      local size = self:byte(pos)
      if size == 0 then
        break
      end
      pos = pos + 1
      offsets[i] = {
        pos,
        size >= 192 and 1 or size
      }
      if size >= 192 then
        break
      end
      pos = pos + size
    end
    return offsets
  end,
  _get_labels = function(self)
    local labels = { }
    local offs = self.labels_offsets
    for i = 1, #offs do
      labels[#labels + 1] = self:str(unpack(offs[i]))
    end
    return labels
  end,
  _get_qtype_offset = function(self)
    local offs = self.labels_offsets
    local pos, size
    do
      local _obj_0 = offs[#offs]
      pos, size = _obj_0[1], _obj_0[2]
    end
    return pos + size + 1
  end,
  _get_qtype = function(self)
    return self:short(self.qtype_offset)
  end,
  _get_qclass = function(self)
    return self:short(self.qtype_offset + 2)
  end,
  _get_qname = function(self)
    return concat(self.labels, ".")
  end,
  _get_length = function(self)
    return self.qtype_offset + 4
  end
})
