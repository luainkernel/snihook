concat = table.concat
cfg = require"snihook.config"
xdp = require"xdp"
xdp_action = require"linux.xdp"
:register = require"netfilter"
:action, :inet, :proto, ip: {:pri} = require"linux.nf"
:ntoh16, :time = require"linux"
:range, :wrap = require"ipparse.fun"
require"ipparse"
IP = require"ipparse.l3.ip"
:collect = require"ipparse.l3.fragmented_ip4"
TCP = require"ipparse.l4.tcp"
UDP = require"ipparse.l4.udp"
QUIC = require"ipparse.l4.quic"
TLS = require"ipparse.l7.tls"
DNS = require"ipparse.l7.dns"
TLSHandshake = require"ipparse.l7.tls.handshake"
TLSClientHello = require"ipparse.l7.tls.handshake.client_hello"
SNI = require"ipparse.l7.tls.handshake.extension.server_name"
mailbox = require"mailbox"
:map = require"rcu"
logger = require"snihook.log"
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
quic_pending = {}
local quic_outbox
local quic_verdicts

flow_id = (src, spt, dst, dpt) -> "#{IP.ip2s(src)}:#{spt}>#{IP.ip2s(dst)}:#{dpt}"


filter_sni = (ip, whitelist) =>
  pkt = @
  return unless ip.protocol == IP.proto.TCP
  tcp = TCP.parse pkt, ip.data_off
  return unless tcp

  id = flow_id ip.src, tcp.spt, ip.dst, tcp.dpt
  rev = flow_id ip.dst, tcp.dpt, ip.src, tcp.spt
  if allowed_tls[id] or allowed_tls[rev]
    now = seconds!
    allowed_tls[id] = now
    allowed_tls[rev] = now
    log.debug "TLS cache hit for flow #{id}" if log
    return true, nil

  return unless tcp.dpt == 443
  return unless tcp.data_off and tcp.data_off <= #pkt
  return unless (#pkt - tcp.data_off + 1) >= 5  -- TLS record header size

  parsed, verdict, msg = pcall ->
    tls = TLS.parse pkt, tcp.data_off
    return unless tls and tls.type == TLS.record_types.handshake

    hs, hs_off = TLSHandshake.parse pkt, tls.data_off
    return unless hs and hs.type == TLSHandshake.message_types.client_hello

    ch = TLSClientHello.parse pkt, hs_off
    return unless ch and ch.extensions and #ch.extensions > 0

    for ext in TLSHandshake.iter_extensions ch.extensions
      continue unless ext and ext.type == TLSHandshake.extensions.server_name
      sni = SNI.parse ext.data
      continue unless sni and sni.name and #sni.name > 0
      log.debug "TLS ClientHello SNI=#{sni.name}" if log
      ok, reason = check sni.name, whitelist
      if ok
        now = seconds!
        allowed_tls[id] = now
        allowed_tls[rev] = now
      return ok, "TLS SNI #{reason}"
  unless parsed
    log.debug "TLS parse error on flow #{id}: #{verdict}" if log
    return
  verdict, msg


filter_dns = (ip, whitelist) =>
  pkt = @
  return unless ip.protocol == IP.proto.UDP
  udp = UDP.parse pkt, ip.data_off
  return unless udp and udp.dpt == 53

  parsed, dns = pcall DNS.parse, pkt, udp.data_off, false
  unless parsed
    log.debug "DNS parse error on UDP #{udp.spt}->#{udp.dpt}: #{dns}" if log
    return
  return unless dns and dns.question and dns.question.name and #dns.question.name > 0

  log.debug "DNS query for #{dns.question.name}" if log
  ok, reason = check dns.question.name, whitelist
  ok, "DNS #{reason}"


maybe_quic_initial = (payload) ->
  return false unless payload and #payload > 0
  parsed, q = pcall QUIC.parse, payload
  return false unless parsed and q and q.long_header
  q.pkt_type == 0x00


filter_quic = (ip, whitelist, skb=nil) =>
  pkt = @
  return unless ip.protocol == IP.proto.UDP
  udp = UDP.parse pkt, ip.data_off
  return unless udp and (udp.dpt == 443 or udp.spt == 443)

  id = flow_id ip.src, udp.spt, ip.dst, udp.dpt
  rev = flow_id ip.dst, udp.dpt, ip.src, udp.spt
  verdict = quic_verdicts and (quic_verdicts[id] or quic_verdicts[rev])
  if verdict
    quic_pending[id] = nil
    quic_pending[rev] = nil
    return true, nil if verdict > 0
    return false, nil

  payload = pkt\sub udp.data_off
  return unless #payload > 0
  t = seconds!
  pending = quic_pending[id] or quic_pending[rev]
  initial = maybe_quic_initial payload

  unless quic_outbox
    log.warning "QUIC parser runtime unavailable, dropping UDP/443 flow" if log
    return false, nil

  unless pending or initial
    log.debug "QUIC non-initial flow allowed (not pending) for flow #{id}" if log
    return true, nil
  return false, nil if pending and not initial

  ifindex = 0
  frame = ""
  if skb
    ok_if, v_if = pcall skb.ifindex, skb
    if ok_if and v_if then ifindex = v_if
    ok_frame, v_frame = pcall (-> skb\data"mac"\getstring 0)
    if ok_frame and v_frame then frame = v_frame

  msg = string.pack ">s2H s2H s4 I4 s4 s4", ip.src, udp.spt, ip.dst, udp.dpt, payload, ifindex, frame, pkt
  sent, err = pcall quic_outbox.send, quic_outbox, msg
  unless sent
    log.warning "QUIC packet enqueue failed: #{err}" if log
    quic_pending[id] = t
    quic_pending[rev] = t
    return false, nil

  quic_pending[id] = t
  quic_pending[rev] = t
  unless pending
    log.debug "QUIC flow pending inspection (dropped fail-closed): #{IP.ip2s(ip.src)}:#{udp.spt} -> #{IP.ip2s(ip.dst)}:#{udp.dpt}" if log
  log.debug "Queued UDP/443 packet for QUIC parser (#{IP.ip2s(ip.src)}:#{udp.spt} -> #{IP.ip2s(ip.dst)}:#{udp.dpt})" if log
  false, nil


_filters = dns: filter_dns, sni: filter_sni, quic: filter_quic


(whitelist, quic_queue=nil, quic_event=nil, _quic_verdicts=nil) ->
  log = logger cfg.log_level, "snihook", rate_limit_window: cfg.log_rate_limit_window, rate_limit_burst: cfg.log_rate_limit_burst
  quic_verdicts = _quic_verdicts
  if quic_queue and quic_event
    quic_outbox = mailbox.outbox quic_queue, quic_event
  else
    log.warning "QUIC outbox not configured; QUIC flows will be dropped fail-closed"
  filters = cfg.filters
  report = {[true]: log.info, [false]: log.notice}
  gc = 0

  is_allowed = (pkt, skb=nil) ->
    return true if not pkt
    ip = IP.parse pkt
    log.debug "IP: src #{IP.ip2s ip.src}, dst #{IP.ip2s ip.dst}"

    for _, name in ipairs filters
      if filter = _filters[name]
        ok, msg = filter pkt, ip, whitelist, skb
        if ok ~= nil
          report[ok](msg) if msg
          return ok, msg
      else
        log.warning "Unknown filter #{name}"

    t = seconds!
    if t - gc > 60
      for k, v in pairs allowed_tls
        if t - v > 86400
          allowed_tls[k] = nil
      if quic_verdicts
        map quic_verdicts, =>
          k = @
          v = quic_verdicts[k]
          if v and t - math.abs(v) > 300
            quic_verdicts[k] = nil
      for k, v in pairs quic_pending
        if t - v > 10
          quic_pending[k] = nil
      gc = t

    l4_port = nil
    switch ip.protocol
      when IP.proto.UDP
        udp = UDP.parse pkt, ip.data_off
        l4_port = udp.dpt if udp
      when IP.proto.TCP
        tcp = TCP.parse pkt, ip.data_off
        l4_port = tcp.dpt if tcp

    log.debug "#{IP.ip2s ip.src} -> #{IP.ip2s ip.dst} (#{(IP.proto[ip.protocol] or ip.protocol)} #{l4_port or '?'}) allowed"
    true, nil


  if cfg.xdp
    DROP = cfg.activate and xdp_action.DROP or xdp_action.PASS
    PASS = xdp_action.PASS
    log.debug "XDP: activate=#{cfg.activate} DROP=#{DROP} PASS=#{PASS}"
    xdp.attach =>
      pkt = @data"net"\getstring 0
      is_allowed(pkt, nil) and PASS or DROP

  if cfg.netfilter
    DROP = cfg.activate and action.DROP or action.ACCEPT
    ACCEPT = action.ACCEPT
    log.debug "Netfilter: activate=#{cfg.activate} DROP=#{DROP} ACCEPT=#{ACCEPT}"
    pfs = {}
    hooknum = inet.FORWARD
    priority = pri.FILTER
    switch cfg.mode
      when "bridge"
        pfs = {proto.BRIDGE}
        priority = pri.FILTER_BRIDGED
      when "router"
        pfs = {proto.IPV4, proto.IPV6}
      when "local"
        pfs = {proto.INET}
        hooknum = inet.POST_ROUTING
    for pf in *pfs
      register {
        :pf, :hooknum, :priority,
        hook: =>
          pkt = @data"net"\getstring 0
          is_allowed(pkt, @) and ACCEPT or DROP
      }
