concat = table.concat
cfg = require"snihook.config"
mailbox = require"mailbox"
lunatik = require"lunatik"
raw = require"socket.raw"
socket = require"socket"
:af, :sock, :ipproto = require"linux.socket"
:shouldstop = require"thread"
:time, :schedule = require"linux"
:range, :wrap = require"ipparse.fun"
IP = require"ipparse.l3.ip"
:checksum = require"ipparse.l3.lib"
UDP = require"ipparse.l4.udp"
QUIC = require"ipparse.l4.quic"
QSession = require"ipparse.l7.quic.session"
logger = require"snihook.log"


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


flow_id = (src, spt, dst, dpt) -> "#{src}:#{spt}>#{dst}:#{dpt}"


canonical_flow = (id, rev) -> (id < rev) and "#{id}|#{rev}" or "#{rev}|#{id}"


decode_packet = (msg) ->
  ok, src, spt, dst, dpt, payload, ifindex, frame, ip_packet, off = pcall string.unpack, ">s2H s2H s4 I4 s4 s4", msg
  return nil, src unless ok
  return nil, "trailing bytes in message" unless off - 1 == #msg
  {:src, :spt, :dst, :dpt, :payload, :ifindex, :frame, :ip_packet}


is_timeout = (err) ->
  msg = "#{err}"
  msg\find("timeout") or msg\find("timed out") or msg\find("ETIME")


get_raw_socket = (sockets, ifindex) ->
  return nil, "invalid ifindex #{ifindex}" unless ifindex and ifindex > 0
  return sockets[ifindex] if sockets[ifindex]
  ok, sock_or_err = pcall raw.bind, nil, ifindex
  return nil, sock_or_err unless ok and sock_or_err
  sockets[ifindex] = sock_or_err
  sock_or_err


split_quic_payload = (payload) ->
  packets, err = QUIC.split_datagrams payload, 1
  return nil, err unless packets
  parts = [p.data for p in *packets]
  return nil, "empty QUIC payload while splitting" if #parts == 0
  parts


split_ipv4_gso_udp = (ip_packet, payload) ->
  return nil, "missing ip_packet bytes" unless ip_packet and #ip_packet >= 28
  b1 = ip_packet\byte 1
  version = (b1 >> 4) & 0x0F
  ihl = b1 & 0x0F
  return nil, "not an IPv4 packet" unless version == 4
  return nil, "IPv4 options not supported in relay fallback" unless ihl == 5
  ip_hlen = ihl * 4
  return nil, "short IPv4 packet" unless #ip_packet >= ip_hlen + 8

  proto = ip_packet\byte 10
  return nil, "not UDP" unless proto == 17

  tos = ip_packet\byte 2
  ip_id = string.unpack ">H", ip_packet, 5
  frag = string.unpack ">H", ip_packet, 7
  ttl = ip_packet\byte 9
  src = ip_packet\sub 13, 16
  dst = ip_packet\sub 17, 20

  udp_hdr = ip_packet\sub ip_hlen + 1, ip_hlen + 8
  spt, dpt = string.unpack ">HH", udp_hdr

  parts, err = split_quic_payload payload
  return nil, err unless parts and #parts > 0

  packets = {}
  for i, part in ipairs parts
    udp_len = 8 + #part
    total_len = ip_hlen + udp_len
    this_id = (ip_id + i - 1) & 0xFFFF
    ip_hdr_wo = string.pack ">BBHHHBBH", b1, tos, total_len, this_id, frag, ttl, proto, 0
    ip_hdr = ip_hdr_wo .. src .. dst
    csum = checksum ip_hdr
    ip_hdr = string.pack(">BBHHHBBH", b1, tos, total_len, this_id, frag, ttl, proto, csum) .. src .. dst
    udp = string.pack(">HHHH", spt, dpt, udp_len, 0) .. part
    packets[#packets + 1] = ip_hdr .. udp
  packets


is_linklocal_v6 = (addr) ->
  return false unless addr and #addr == 16
  b1 = addr\byte 1
  b2 = addr\byte 2
  b1 == 0xFE and (b2 & 0xC0) == 0x80


pack_sockaddr_in6 = (addr, port=0, ifindex=0) ->
  scope_id = is_linklocal_v6(addr) and (tonumber(ifindex) or 0) or 0
  string.pack(">H", port) .. string.pack(">I4", 0) .. addr .. string.pack("=I4", scope_id)


split_ipv6_gso_udp = (ip_packet, payload) ->
  return nil, "missing ip_packet bytes" unless ip_packet and #ip_packet >= 48
  ip_h, l4_off = IP.parse ip_packet, 1
  return nil, "not an IPv6 packet" unless ip_h and ip_h.version == 6
  return nil, "IPv6 next header is not UDP" unless ip_h.next_header == 17
  udp_h = UDP.parse ip_packet, l4_off
  return nil, "short IPv6 UDP header" unless udp_h

  parts, err = split_quic_payload payload
  return nil, err unless parts and #parts > 0

  packets = {}
  for _, part in ipairs parts
    udp = UDP.new spt: udp_h.spt, dpt: udp_h.dpt, checksum: 0, data: part
    udp_pkt = tostring udp
    udp.checksum = UDP.checksum6 ip_h.src, ip_h.dst, udp_pkt
    packets[#packets + 1] = tostring udp
  packets


send_ipv6_udp = (raw_ip6, udp_pkt, dst, dpt, ifindex) ->
  addrs = {
    pack_sockaddr_in6(dst, dpt, ifindex)
    pack_sockaddr_in6(dst, 0, ifindex)
    pack_sockaddr_in6(dst, dpt, 0)
    pack_sockaddr_in6(dst, 0, 0)
  }
  last_err = nil
  max_tries = 4
  for sockaddr in *addrs
    for _ = 1, max_tries
      ok, ret = pcall raw_ip6.send, raw_ip6, udp_pkt, sockaddr
      return true if ok and ret and ret > 0
      last_err = ret
      break unless "#{ret}"\find "ENOBUFS"
      schedule 1
  nil, last_err


relay_ipv4_with_split = (sockets, packet) ->
  raw_ip = sockets._raw_ip
  unless raw_ip
    ok_raw, raw_or_err = pcall socket.new, af.INET, sock.RAW, ipproto.RAW
    return nil, raw_or_err unless ok_raw and raw_or_err
    raw_ip = raw_or_err
    sockets._raw_ip = raw_ip

  ok_u32, dst_u32 = pcall string.unpack, ">I4", packet.dst
  return nil, "invalid IPv4 destination format" unless ok_u32 and dst_u32

  parts, err = split_ipv4_gso_udp packet.ip_packet, packet.payload
  return nil, err unless parts

  sent = 0
  for p in *parts
    ok, ret = pcall raw_ip.send, raw_ip, p, dst_u32, 0
    return nil, ret unless ok and ret and ret > 0
    sent += 1
  true, sent


relay_ipv6_with_split = (sockets, packet) ->
  raw_ip6 = sockets._raw_ip6
  unless raw_ip6
    ok_raw, raw_or_err = pcall socket.new, af.INET6, sock.RAW, ipproto.UDP
    return nil, raw_or_err unless ok_raw and raw_or_err
    raw_ip6 = raw_or_err
    sockets._raw_ip6 = raw_ip6

  parts, err = split_ipv6_gso_udp packet.ip_packet, packet.payload
  return nil, err unless parts

  sent = 0
  for udp_pkt in *parts
    ok, ret = send_ipv6_udp raw_ip6, udp_pkt, packet.dst, packet.dpt, packet.ifindex
    return nil, ret unless ok
    sent += 1
  true, sent


relay_packet = (sockets, packet) ->
  if packet.frame and #packet.frame > 0
    sock, err = get_raw_socket sockets, packet.ifindex
    return nil, err unless sock
    ok, sent_or_err = pcall sock.send, sock, packet.frame
    return nil, sent_or_err unless ok and sent_or_err and sent_or_err > 0
    return true

  return nil, "missing IP packet bytes" unless packet.ip_packet and #packet.ip_packet > 0
  if #packet.dst == 4
    ok_u32, dst_u32 = pcall string.unpack, ">I4", packet.dst
    return nil, "invalid IPv4 destination format" unless ok_u32 and dst_u32

    raw_ip = sockets._raw_ip
    unless raw_ip
      ok_raw, raw_or_err = pcall socket.new, af.INET, sock.RAW, ipproto.RAW
      return nil, raw_or_err unless ok_raw and raw_or_err
      raw_ip = raw_or_err
      sockets._raw_ip = raw_ip

    ok, sent_or_err = pcall raw_ip.send, raw_ip, packet.ip_packet, dst_u32, 0
    if ok and sent_or_err and sent_or_err > 0
      return true
    if (not ok) and "#{sent_or_err}"\find "EMSGSIZE"
      return relay_ipv4_with_split sockets, packet
    return nil, sent_or_err

  if #packet.dst == 16
    raw_ip6 = sockets._raw_ip6
    unless raw_ip6
      ok_raw, raw_or_err = pcall socket.new, af.INET6, sock.RAW, ipproto.UDP
      return nil, raw_or_err unless ok_raw and raw_or_err
      raw_ip6 = raw_or_err
      sockets._raw_ip6 = raw_ip6

    return nil, "short IPv6 packet for relay" unless #packet.ip_packet >= 48
    udp_pkt = packet.ip_packet\sub 41
    ok, sent_or_err = send_ipv6_udp raw_ip6, udp_pkt, packet.dst, packet.dpt, packet.ifindex
    return true if ok
    if "#{sent_or_err}"\find("EMSGSIZE") or "#{sent_or_err}"\find("EINVAL")
      return relay_ipv6_with_split sockets, packet
    return nil, sent_or_err

  nil, "unsupported IP address size #{#packet.dst}"


extract_initial_packets = (payload) ->
  datagrams, err = QUIC.split_datagrams payload, 1
  return nil, err unless datagrams
  packets = {}
  for d in *datagrams
    packets[#packets + 1] = d.data if d.header and d.header.pkt_type == 0x00

  packets


-> -- dedicated sleepable QUIC parser runtime
  log = logger cfg.log_level, "snihook/quic", rate_limit_window: cfg.log_rate_limit_window, rate_limit_burst: cfg.log_rate_limit_burst
  env = lunatik._ENV
  quic_queue = env.snihook_quic_queue
  quic_event = env.snihook_quic_event
  whitelist = env.snihook_quic_whitelist
  quic_verdicts = env.snihook_quic_verdicts

  unless quic_queue and quic_event and whitelist and quic_verdicts
    log.warning "QUIC runtime not configured"
    return

  inbox = mailbox.inbox quic_queue, quic_event
  sessions = {}
  pending_packets = {}
  raw_sockets = {}
  session_count = 0
  backend_error = nil
  gc = 0

  while not shouldstop!
    ok, msg = pcall inbox.receive, inbox, 100
    unless ok
      log.warning "QUIC inbox receive failed: #{msg}" unless is_timeout msg
      continue
    log.debug "QUIC inbox received: #{#msg}"
    continue unless msg

    packet, err = decode_packet msg
    unless packet
      log.warning "Discarding malformed QUIC packet message: #{err}"
      continue

    id = flow_id packet.src, packet.spt, packet.dst, packet.dpt
    rev = flow_id packet.dst, packet.dpt, packet.src, packet.spt
    conn = canonical_flow id, rev
    pending = pending_packets[conn]
    unless pending
      pending = {}
      pending_packets[conn] = pending
    pending[#pending + 1] = packet

    verdict = quic_verdicts[id] or quic_verdicts[rev]
    if verdict
      if verdict > 0
        relayed = 0
        for queued in *pending
          forwarded, relay_err = relay_packet raw_sockets, queued
          if forwarded
            relayed += 1
          else
            log.warning "Failed to relay queued QUIC packet: #{relay_err}"
      pending_packets[conn] = nil
      continue

    initial_packets, pkt_err = extract_initial_packets packet.payload
    unless initial_packets
      log.debug pkt_err
      continue
    continue unless #initial_packets > 0

    session = sessions[conn]
    unless session
      continue if backend_error
      ok_new, session_or_err = pcall QSession.new
      unless ok_new and session_or_err
        backend_error = session_or_err
        log.warning "QUIC parser disabled: #{session_or_err}"
        continue
      session = session_or_err
      sessions[conn] = session
      session_count += 1
      log.debug "Created QUIC session #{conn}"

    for quic_packet in *initial_packets
      pushed, push_err = session\push quic_packet
      unless pushed
        log.debug "QUIC Initial parse/decrypt pending: #{push_err}" if push_err
        continue

    sni = session\sni!
    unless sni and #sni > 0
      log.debug "QUIC SNI not yet available (CRYPTO stream=#{#(session\crypto_stream!)} bytes)"
      continue

    log.debug "QUIC SNI check: #{sni}"
    allowed, reason = check sni, whitelist
    verdict = (allowed and 1 or -1) * seconds!
    quic_verdicts[id] = verdict
    quic_verdicts[rev] = verdict
    if allowed and pending
      relayed = 0
      for queued in *pending
        forwarded, relay_err = relay_packet raw_sockets, queued
        if forwarded
          relayed += 1
        else
          log.warning "Failed to relay queued QUIC packet: #{relay_err}"
      log.debug "Relayed #{relayed}/#{#pending} queued QUIC packet(s)" if relayed > 0
      log.debug "QUIC relay flow #{IP.ip2s(packet.src)}:#{packet.spt} -> #{IP.ip2s(packet.dst)}:#{packet.dpt}" if relayed > 0
    pending_packets[conn] = nil
    log[allowed and "info" or "notice"] "QUIC SNI #{reason}"
    log.debug "QUIC SNI flow #{IP.ip2s(packet.src)}:#{packet.spt} -> #{IP.ip2s(packet.dst)}:#{packet.dpt}"

    t = seconds!
    if session_count > 1000 or t - gc > 300
      sessions = {}
      pending_packets = {}
      session_count = 0
      gc = t

  for _, sock in pairs raw_sockets
    pcall sock.close, sock
