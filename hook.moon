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
UDP = require"ipparse.l4.udp"
TLS = require"ipparse.l7.tls"
DNS = require"ipparse.l7.dns"
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


check = (whitelist) =>
  if whitelist[@]
    return true, "#{@} allowed"
  domain_parts = [ part for part in @gmatch"[^%.]+" ]
  for i = 2, #domain_parts
    domain = concat [ part for part in *domain_parts[i,] ], "."
    if whitelist[domain]
      return true, "#{@} allowed as a subdomain of #{domain}"
  return false, "#{@} BLOCKED"


filter_sni = (whitelist) =>
  return if @protocol ~= TCP.protocol_type

  tcp = TCP @data
  return if tcp\is_empty! or tcp.dport ~= TLS.iana_port

  tls = TLS tcp.data
  return if tls\is_empty! or tls.type ~= TLSHandshake.record_type

  hshake = TLSHandshake tls.data
  return if hshake\is_empty! or hshake.type ~= TLSClientHello.message_type

  client_hello = TLSClientHello hshake.data

  if sni = get_first client_hello\iter_extensions!, => @type == SNI.extension_type
    sni = sni.server_name
    ok, msg = check sni, whitelist
    if ok
      return CONTINUE, log.info"#{@src} -> #{msg} (SNI)"
    else
      return DROP, log.notice"#{@src} -> #{msg} (SNI)"


filter_dns = (whitelist) =>
  return if @protocol ~= UDP.protocol_type

  udp = UDP @data
  return if udp\is_empty! or udp.sport ~= DNS.iana_port

  dns = DNS udp.data
  return if dns\is_empty!

  if q = dns.question
    if domain = q.qname
      for a in *dns.answers
        log.info "DNS answer type: #{DNS.types[a.type]}, rdata: #{concat a.rdata, ','}"
      ok, msg = check domain, whitelist
      if ok
        return CONTINUE, log.info"#{@dst} -> #{msg} (DNS)"
      else
        return DROP, log.notice"#{@dst} -> #{msg} (DNS)"


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

    for filter in *{filter_sni, filter_dns}
      res = filter ip, whitelist
      log.debug"RES: #{res}"
      return res if res

    CONTINUE


  register :pf, :hooknum, :priority, :hook for pf in *pfs

