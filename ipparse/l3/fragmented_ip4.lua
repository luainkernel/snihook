local subclass, Object
do
  local _obj_0 = require("ipparse")
  subclass, Object = _obj_0.subclass, _obj_0.Object
end
local IP4 = require("ipparse.l3.ip4")
local data_new
data_new = require("data").new
local insert
insert = table.insert
return subclass(IP4, {
  new = function(self, obj)
    if obj == nil then
      obj = { }
    end
    obj.off = obj.off or 0
    return Object.new(self, obj)
  end,
  insert = function(self, fragment)
    do
      local prec = self[1]
      if prec then
        assert(fragment.id == prec.id)
        for i = 1, #self do
          if fragment.fragmentation_off < self[i].fragmentation_off then
            insert(self, i, fragment)
            return self
          end
        end
        self[#self + 1] = fragment
        return self
      end
    end
    self[1] = fragment
    return self
  end,
  is_complete = function(self)
    if self[#self].mf ~= 0 then
      return false
    end
    for i = 2, #self do
      local this, prec = self[i], self[i - 1]
      if (this.fragmentation_off << 3) ~= (prec.fragmentation_off << 3) + prec.data_len then
        return false
      end
    end
    return true
  end,
  _get_skb = function(self)
    assert(self:is_complete(), "Can't access payload of incomplete fragmented packet")
    local fragmentation_off, data_len
    do
      local _obj_0 = self[#self]
      fragmentation_off, data_len = _obj_0.fragmentation_off, _obj_0.data_len
    end
    local skb = data_new((fragmentation_off << 3) + data_len)
    local off = 0
    local _skb
    _skb = self[1].skb
    for j = 0, #_skb - 1 do
      skb:setbyte(off, _skb:getbyte(j))
      off = off + 1
    end
    for i = 2, #self do
      local data_off
      do
        local _obj_0 = self[i]
        _skb, data_off = _obj_0.skb, _obj_0.data_off
      end
      for j = 0, #_skb - 1 do
        skb:setbyte(off, _skb:getbyte(data_off + j))
        off = off + 1
      end
    end
    return skb
  end
})
