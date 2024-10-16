:concat = table
cfg = require"snihook.config"
:log_level, :mode, :filters = cfg
xdp = require"xdp"
nf = require"netfilter"
:ntoh16 = require"linux"
require"ipparse"
IP = require"ipparse.l3.auto_ip"
:collect = require"ipparse.l3.fragmented_ip4"
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


check = (whitelist) =>
  if whitelist[@]
    return true, "#{@} allowed"
  domain_parts = [ part for part in @gmatch"[^%.]+" ]
  for i = 2, #domain_parts
    domain = concat [ part for part in *domain_parts[i,] ], "."
    if whitelist[domain]
      return true, "#{@} allowed as a subdomain of #{domain}"
  false, "#{@} BLOCKED"


filter_sni = (whitelist) =>
  log.debug"SNI filter #{@protocol == TCP.protocol_type}"
  return if @protocol ~= TCP.protocol_type

  tcp = TCP @data
  --log.debug l for l in *tcp.hexdump
  return if tcp\is_empty! or tcp.dport ~= TLS.iana_port

  tls = TLS tcp.data
  --log.debug l for l in *tls.hexdump
  return if tls\is_empty! or tls.type ~= TLSHandshake.record_type

  hshake = TLSHandshake tls.data
  return if hshake\is_empty! or hshake.type ~= TLSClientHello.message_type

  client_hello = TLSClientHello hshake.data
  -- log.debug l for l in *client_hello.hexdump

  if sni = get_first client_hello\iter_extensions!, => @type == SNI.extension_type
    sni = sni.server_name
    ok, msg = check sni, whitelist
    ok, "#{@src} -> #{msg} (SNI)"


filter_dns = (whitelist) =>
  protocol = @protocol
  log.debug"DNS filter"
  local pkt, is_tcp
  if protocol == UDP.protocol_type
    pkt = UDP @data
  elseif protocol == TCP.protocol_type and TCP(@data)
    pkt = TCP @data
    is_tcp = true
  else return

  log.debug"#{pkt.__name} #{pkt.sport} #{pkt.dport}"
  return if pkt\is_empty! or (pkt.dport ~= DNS.iana_port and pkt.sport ~= DNS.iana_port)

  dns = DNS pkt.data
  dns.off += 2 if is_tcp  -- DNS over TCP has a size field in first 2-bits field
  return if dns\is_empty!

  if q = dns.question
    if domain = q.qname
      if dns.answers
        for a in *dns.answers
          log.info "DNS answer type: #{DNS.types[a.type]}, rdata: #{concat a.rdata, ','}"
      ok, msg = check domain, whitelist
      ok, "#{@src} -> #{@dst} #{msg} (DNS)"


_filters = dns: filter_dns, sni: filter_sni


(whitelist) ->
  log = logger log_level, "snihook"
  report = {[true]: log.info, [false]: log.notice}

  is_allowed = =>
    return true if not @ or @is_empty!
    log.debug "IP: src #{@src}, dst #{@dst}"
    if @is_fragment!
      log.debug"Fragment detected"
      f_ip = collect @
      return true unless f_ip  -- Allow fragments: blocking the last one will be enough
      log.debug"Last fragment received"
      @ = f_ip
    --log.debug l for l in *@hexdump

    for name in *filters
      if filter = _filters[name]
        ok, msg = filter @, whitelist
        return ok, report[ok](msg) if ok ~= nil
      else
        log.warning "Unknown filter #{name}"

    true


  if cfg.xdp
    {:PASS, :DROP} = xdp.action
    DROP = PASS if not cfg.activate
    xdp.attach (skb, arg) ->
      off = ntoh16 arg\getuint16 0
      is_allowed(IP :skb, :off) and PASS or DROP

  if cfg.netfilter
    local register, pfs, hooknum, priority, CONTINUE
    switch mode
      when "bridge"
        :register, family: {:BRIDGE}, bridge_hooks: {FORWARD: hooknum}, bridge_priority: {FILTER_BRIDGED: priority}, action: {:CONTINUE, :DROP} = nf
        pfs = {BRIDGE}
      when "router"
        :register, family: {:IPV6, :IPV4}, inet_hooks: {FORWARD: hooknum}, ip_priority: {FILTER: priority}, action: {:CONTINUE, :DROP} = nf
        pfs = {IPV6, IPV4}
    DROP = CONTINUE if not cfg.activate
    for pf in *pfs
      register :pf, :hooknum, :priority, hook: (skb) ->
        is_allowed(IP :skb) and CONTINUE or DROP

