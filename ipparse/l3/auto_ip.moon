IP = require"ipparse.l3.ip"
IP4 = require"ipparse.l3.ip4"
IP6 = require"ipparse.l3.ip6"

=>
  ip = IP skb: @
  switch ip.version
    when 4
      IP4 skb: @
    when 6
      IP6 skb: @
