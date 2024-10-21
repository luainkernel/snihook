concat = table.concat
cfg = require"snihook.config"
xdp = require"xdp"
nf = require"netfilter"
linux = require"linux"
ntoh16, time = linux.ntoh16, linux.time
range, wrap = do
  _ = require"fun"
  _.range, _.wrap
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


seconds = -> time! / 1000000000


check = (whitelist) =>
  if whitelist[@]
    return true, "#{@} allowed"
  domain_parts = wrap(@gmatch"[^%.]+")\toarray!
  for i = 2, #domain_parts
    domain = concat range(i, #domain_parts)\map(=> domain_parts[@])\toarray!, "."
    if whitelist[domain]
      return true, "#{@} allowed as a subdomain of #{domain}"
  false, "#{@} BLOCKED"


allowed_tls = {}

filter_sni = (whitelist) =>
  log.debug"SNI filter"
  return if @protocol ~= TCP.protocol_type

  tcp = TCP @data
  log.debug l for l in tcp\hexdump!
  return if tcp\is_empty! or tcp.dport ~= TLS.iana_port

  tls = TLS tcp.data
  return if tls\is_empty!
  if tls.type ~= TLSHandshake.record_type  -- This rule is quite fussy: it will block any tls traffic without SNI
    return not not (allowed_tls["#{@src}_#{@dst}"] or allowed_tls["#{@dst}_#{@src}"]) or false, "#{@src} #{@dst} BLOCKED (TLS)"

  hshake = TLSHandshake tls.data
  if hshake\is_empty! or hshake.type ~= TLSClientHello.message_type
    return true, "TLS Handshake allowed"

  client_hello = TLSClientHello hshake.data

  if sni = get_first client_hello\iter_extensions!, => @type == SNI.extension_type
    ok, msg = check sni.server_name, whitelist
    allowed_tls["#{@src}_#{@dst}"] = seconds! if ok
    ok, "#{@src} -> #{msg} (SNI)"


filter_dns = (whitelist) =>
  protocol = @protocol
  log.debug"DNS filter"
  local pkt, is_tcp
  if protocol == UDP.protocol_type
    pkt = UDP @data
  elseif protocol == TCP.protocol_type and TCP @data
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
      if answers = dns.answers
        for i = 1, #answers
          a = answers[i]
          log.info "DNS answer type: #{DNS.types[a.type]}, rdata: #{concat a.rdata, ','}"
      ok, msg = check domain, whitelist
      ok, "#{@src} -> #{@dst} #{msg} (DNS)"


block_quic = =>
  return if @protocol ~= UDP.protocol_type
  pkt = UDP @data
  false, "QUIC blocked #{@src} -> #{@dst}" if pkt.dport == 443


_filters = dns: filter_dns, sni: filter_sni, quic: block_quic


(whitelist) ->
  log = logger cfg.log_level, "snihook"
  filters = cfg.filters
  report = {[true]: log.info, [false]: log.notice}
  gc = 0

  is_allowed = =>
    return true if not @ or @is_empty!
    log.debug "IP: src #{@src}, dst #{@dst}"
    if @is_fragment!
      log.debug"Fragment detected: #{@length}"
      f_ip = collect @
      return true unless f_ip  -- Allow fragments: blocking the last one will be enough
      log.debug"Last fragment received"
      @ = f_ip

    for _, name in ipairs filters
      if filter = _filters[name]
        ok, msg = filter @, whitelist
        return ok, report[ok](msg) if ok ~= nil
      else
        log.warning "Unknown filter #{name}"

    t = seconds!
    if t - gc > 60
      for k, v in pairs allowed_tls
        if t - v > 86400
          allowed_tls[k] = nil
      gc = t

    true, log.info"#{@src} -> #{@dst} (#{@protocol} #{UDP(@data).dport}) allowed"


  if cfg.xdp
    {:PASS, :DROP} = xdp.action
    DROP = PASS if not cfg.activate
    xdp.attach (skb, arg) ->
      off = ntoh16 arg\getuint16 0
      is_allowed(IP :skb, :off) and PASS or DROP

  if cfg.netfilter
    local register, pfs, hooknum, priority, CONTINUE, DROP
    switch cfg.mode
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

