local subclass, Packet
do
  local _obj_0 = require("ipparse")
  subclass, Packet = _obj_0.subclass, _obj_0.Packet
end
local concat
concat = table.concat
return subclass(Packet, {
  __name = "DNSRessourceRecord",
  _get_labels_offsets = function(self)
    local offsets = { }
    local pos = 0
    for i = 1, 1000 do
      local size = self:byte(pos)
      if size == 0 then
        break
      end
      pos = pos + 1
      offsets[#offsets + 1] = {
        pos,
        (size & 0xC0 and 0 or size),
        size & 0x3F
      }
      if size & 0xC0 then
        break
      end
      pos = pos + size
    end
    return offsets
  end,
  _get_labels = function(self)
    local labels = { }
    local offs = self.labels_offsets
    for _index_0 = 1, #offs do
      local _des_0 = offs[_index_0]
      local o, len, ptr
      o, len, ptr = _des_0[1], _des_0[2], _des_0[3]
      if len == 0 then
        for _index_1 = 1, #offs do
          local _des_1 = offs[_index_1]
          local _o, _len
          _o, _len = _des_1[1], _des_1[2]
          if _o == ptr then
            o, len = _o, _len
            break
          end
        end
      end
      labels[#labels + 1] = self:str(o, len)
    end
    return labels
  end,
  _get_type_offset = function(self)
    local offs = self.labels_offsets
    local pos, size
    do
      local _obj_0 = offs[#offs]
      pos, size = _obj_0[1], _obj_0[2]
    end
    return pos + size + 1
  end,
  _get_type = function(self)
    return self:short(self.type_offset)
  end,
  _get_class = function(self)
    return self:short(self.type_offset + 2)
  end,
  _get_ttl = function(self)
    return self:word(self.type_offset + 4)
  end,
  _get_rdlength = function(self)
    return self:short(self.type_offset + 8)
  end,
  _get_rdata = function(self)
    local _accum_0 = { }
    local _len_0 = 1
    for off = 0, self.rdlength - 1 do
      _accum_0[_len_0] = self:byte(self.type_offset + 10 + off)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end,
  _get_name = function(self)
    return concat(self.labels, ".")
  end,
  _get_length = function(self)
    return self.type_offset + 10 + self.rdlength
  end
})
