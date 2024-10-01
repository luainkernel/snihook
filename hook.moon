:concat = table
:activate, :log_level, :mode = require"snihook.config"
:outbox = require"mailbox"
local register, pfs, hooknum, priority, CONTINUE, DROP
switch mode
  when "bridge"
    :register, family: {:BRIDGE}, bridge_hooks: {FORWARD: hooknum}, bridge_priority: {FILTER_BRIDGED: priority}, action: {:CONTINUE, :DROP} = require"netfilter"
    pfs = {BRIDGE}
  when "router"
    :register, family: {:IPV6, :IPV4}, inet_hooks: {FORWARD: hooknum}, ip_priority: {FILTER: priority}, action: {:CONTINUE, :DROP} = require"netfilter"
    pfs = {IPV6, IPV4}
DROP = activate and DROP or CONTINUE
require"ipparse"
IP = require"ipparse.l3.auto_ip"
Fragmented_IP4 = require"ipparse.l3.fragmented_ip4"
TCP = require"ipparse.l4.tcp"
TLS = require"ipparse.l7.tls"
TLSHandshake = require"ipparse.l7.tls.handshake"
TLSClientHello = require"ipparse.l7.tls.handshake.client_hello"
SNI = require"ipparse.l7.tls.handshake.extension.server_name"
logger = require"log"
local log


get_first = (fn) =>  -- Returns first value of an iterator that matches the condition defined in function fn.
  for v in @
    return v if fn v

fragmented_ips = setmetatable {},  __mode: "kv", __index: (id) =>
  @[id] = Fragmented_IP4!
  log.debug id, @[id]
  @[id]


(whitelist, log_queue, log_evt) ->
  with outbox log_queue, log_evt
    log = logger log_level, "snihook", (...) -> \send ...

  hook = =>
    ip = IP @
    return CONTINUE if not ip or ip\is_empty!
    if ip\is_fragment!
      log.debug"Fragment detected"
      f_ip = fragmented_ips[ip.id]\insert(ip)
      return CONTINUE unless f_ip\is_complete!
      log.debug"Last fragment received"
      ip = f_ip
      fragmented_ips[ip.id] = nil
    return CONTINUE if ip.protocol ~= TCP.protocol_type

    tcp = TCP ip.data
    return CONTINUE if tcp\is_empty! or tcp.dport ~= 443

    tls = TLS tcp.data
    return CONTINUE if tls\is_empty! or tls.type ~= TLSHandshake.record_type

    hshake = TLSHandshake tls.data
    return CONTINUE if hshake\is_empty! or hshake.type ~= TLSClientHello.message_type

    client_hello = TLSClientHello hshake.data

    if sni = get_first client_hello\iter_extensions!, => @type == SNI.extension_type
      sni = sni.server_name
      if whitelist[sni]
        return CONTINUE, log.info"#{ip.src} -> #{sni} allowed."
      sni_parts = [ part for part in sni\gmatch"[^%.]+" ]
      for i = 2, #sni_parts
        domain = concat [ part for part in *sni_parts[i,] ], "."
        if whitelist[domain]
          return CONTINUE, log.info"#{ip.src} -> #{sni} allowed as a subdomain of #{domain}."
      return DROP, log.notice"#{ip.src} -> #{sni} BLOCKED."

    CONTINUE


  register :pf, :hooknum, :priority, :hook for pf in *pfs
