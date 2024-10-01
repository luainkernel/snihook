local IP = require("ipparse.l3.ip")
local IP4 = require("ipparse.l3.ip4")
local IP6 = require("ipparse.l3.ip6")
return function(self)
  local ip = IP({
    skb = self
  })
  local _exp_0 = ip.version
  if 4 == _exp_0 then
    return IP4({
      skb = self
    })
  elseif 6 == _exp_0 then
    return IP6({
      skb = self
    })
  end
end
