local concat = table.concat
local cfg = require("snihook.config")
local mailbox = require("mailbox")
local lunatik = require("lunatik")
local raw = require("socket.raw")
local socket = require("socket")
local af, sock, ipproto
do
  local _obj_0 = require("linux.socket")
  af, sock, ipproto = _obj_0.af, _obj_0.sock, _obj_0.ipproto
end
local shouldstop
shouldstop = require("thread").shouldstop
local time, schedule
do
  local _obj_0 = require("linux")
  time, schedule = _obj_0.time, _obj_0.schedule
end
local range, wrap
do
  local _obj_0 = require("ipparse.fun")
  range, wrap = _obj_0.range, _obj_0.wrap
end
local IP = require("ipparse.l3.ip")
local checksum
checksum = require("ipparse.l3.lib").checksum
local UDP = require("ipparse.l4.udp")
local QUIC = require("ipparse.l4.quic")
local QSession = require("ipparse.l7.quic.session")
local logger = require("snihook.log")
local seconds
seconds = function()
  return time() / 1000000000
end
local check
check = function(self, whitelist)
  if whitelist[self] then
    return true, tostring(self) .. " allowed"
  end
  local domain_parts = wrap(self:gmatch("[^%.]+")):toarray()
  for i = 2, #domain_parts do
    local domain = concat(range(i, #domain_parts):map(function(self)
      return domain_parts[self]
    end):toarray(), ".")
    if whitelist[domain] then
      return true, tostring(self) .. " allowed as a subdomain of " .. tostring(domain)
    end
  end
  return false, tostring(self) .. " BLOCKED"
end
local flow_id
flow_id = function(src, spt, dst, dpt)
  return tostring(src) .. ":" .. tostring(spt) .. ">" .. tostring(dst) .. ":" .. tostring(dpt)
end
local canonical_flow
canonical_flow = function(id, rev)
  return (id < rev) and tostring(id) .. "|" .. tostring(rev) or tostring(rev) .. "|" .. tostring(id)
end
local decode_packet
decode_packet = function(msg)
  local ok, src, spt, dst, dpt, payload, ifindex, frame, ip_packet, off = pcall(string.unpack, ">s2H s2H s4 I4 s4 s4", msg)
  if not (ok) then
    return nil, src
  end
  if not (off - 1 == #msg) then
    return nil, "trailing bytes in message"
  end
  return {
    src = src,
    spt = spt,
    dst = dst,
    dpt = dpt,
    payload = payload,
    ifindex = ifindex,
    frame = frame,
    ip_packet = ip_packet
  }
end
local is_timeout
is_timeout = function(err)
  local msg = tostring(err)
  return msg:find("timeout") or msg:find("timed out") or msg:find("ETIME")
end
local get_raw_socket
get_raw_socket = function(sockets, ifindex)
  if not (ifindex and ifindex > 0) then
    return nil, "invalid ifindex " .. tostring(ifindex)
  end
  if sockets[ifindex] then
    return sockets[ifindex]
  end
  local ok, sock_or_err = pcall(raw.bind, nil, ifindex)
  if not (ok and sock_or_err) then
    return nil, sock_or_err
  end
  sockets[ifindex] = sock_or_err
  return sock_or_err
end
local split_quic_payload
split_quic_payload = function(payload)
  local packets, err = QUIC.split_datagrams(payload, 1)
  if not (packets) then
    return nil, err
  end
  local parts
  do
    local _accum_0 = { }
    local _len_0 = 1
    for _index_0 = 1, #packets do
      local p = packets[_index_0]
      _accum_0[_len_0] = p.data
      _len_0 = _len_0 + 1
    end
    parts = _accum_0
  end
  if #parts == 0 then
    return nil, "empty QUIC payload while splitting"
  end
  return parts
end
local split_ipv4_gso_udp
split_ipv4_gso_udp = function(ip_packet, payload)
  if not (ip_packet and #ip_packet >= 28) then
    return nil, "missing ip_packet bytes"
  end
  local b1 = ip_packet:byte(1)
  local version = (b1 >> 4) & 0x0F
  local ihl = b1 & 0x0F
  if not (version == 4) then
    return nil, "not an IPv4 packet"
  end
  if not (ihl == 5) then
    return nil, "IPv4 options not supported in relay fallback"
  end
  local ip_hlen = ihl * 4
  if not (#ip_packet >= ip_hlen + 8) then
    return nil, "short IPv4 packet"
  end
  local proto = ip_packet:byte(10)
  if not (proto == 17) then
    return nil, "not UDP"
  end
  local tos = ip_packet:byte(2)
  local ip_id = string.unpack(">H", ip_packet, 5)
  local frag = string.unpack(">H", ip_packet, 7)
  local ttl = ip_packet:byte(9)
  local src = ip_packet:sub(13, 16)
  local dst = ip_packet:sub(17, 20)
  local udp_hdr = ip_packet:sub(ip_hlen + 1, ip_hlen + 8)
  local spt, dpt = string.unpack(">HH", udp_hdr)
  local parts, err = split_quic_payload(payload)
  if not (parts and #parts > 0) then
    return nil, err
  end
  local packets = { }
  for i, part in ipairs(parts) do
    local udp_len = 8 + #part
    local total_len = ip_hlen + udp_len
    local this_id = (ip_id + i - 1) & 0xFFFF
    local ip_hdr_wo = string.pack(">BBHHHBBH", b1, tos, total_len, this_id, frag, ttl, proto, 0)
    local ip_hdr = ip_hdr_wo .. src .. dst
    local csum = checksum(ip_hdr)
    ip_hdr = string.pack(">BBHHHBBH", b1, tos, total_len, this_id, frag, ttl, proto, csum) .. src .. dst
    local udp = string.pack(">HHHH", spt, dpt, udp_len, 0) .. part
    packets[#packets + 1] = ip_hdr .. udp
  end
  return packets
end
local is_linklocal_v6
is_linklocal_v6 = function(addr)
  if not (addr and #addr == 16) then
    return false
  end
  local b1 = addr:byte(1)
  local b2 = addr:byte(2)
  return b1 == 0xFE and (b2 & 0xC0) == 0x80
end
local pack_sockaddr_in6
pack_sockaddr_in6 = function(addr, port, ifindex)
  if port == nil then
    port = 0
  end
  if ifindex == nil then
    ifindex = 0
  end
  local scope_id = is_linklocal_v6(addr) and (tonumber(ifindex) or 0) or 0
  return string.pack(">H", port) .. string.pack(">I4", 0) .. addr .. string.pack("=I4", scope_id)
end
local split_ipv6_gso_udp
split_ipv6_gso_udp = function(ip_packet, payload)
  if not (ip_packet and #ip_packet >= 48) then
    return nil, "missing ip_packet bytes"
  end
  local ip_h, l4_off = IP.parse(ip_packet, 1)
  if not (ip_h and ip_h.version == 6) then
    return nil, "not an IPv6 packet"
  end
  if not (ip_h.next_header == 17) then
    return nil, "IPv6 next header is not UDP"
  end
  local udp_h = UDP.parse(ip_packet, l4_off)
  if not (udp_h) then
    return nil, "short IPv6 UDP header"
  end
  local parts, err = split_quic_payload(payload)
  if not (parts and #parts > 0) then
    return nil, err
  end
  local packets = { }
  for _, part in ipairs(parts) do
    local udp = UDP.new({
      spt = udp_h.spt,
      dpt = udp_h.dpt,
      checksum = 0,
      data = part
    })
    local udp_pkt = tostring(udp)
    udp.checksum = UDP.checksum6(ip_h.src, ip_h.dst, udp_pkt)
    packets[#packets + 1] = tostring(udp)
  end
  return packets
end
local send_ipv6_udp
send_ipv6_udp = function(raw_ip6, udp_pkt, dst, dpt, ifindex)
  local addrs = {
    pack_sockaddr_in6(dst, dpt, ifindex),
    pack_sockaddr_in6(dst, 0, ifindex),
    pack_sockaddr_in6(dst, dpt, 0),
    pack_sockaddr_in6(dst, 0, 0)
  }
  local last_err = nil
  local max_tries = 4
  for _index_0 = 1, #addrs do
    local sockaddr = addrs[_index_0]
    for _ = 1, max_tries do
      local ok, ret = pcall(raw_ip6.send, raw_ip6, udp_pkt, sockaddr)
      if ok and ret and ret > 0 then
        return true
      end
      last_err = ret
      if not ((tostring(ret)):find("ENOBUFS")) then
        break
      end
      schedule(1)
    end
  end
  return nil, last_err
end
local relay_ipv4_with_split
relay_ipv4_with_split = function(sockets, packet)
  local raw_ip = sockets._raw_ip
  if not (raw_ip) then
    local ok_raw, raw_or_err = pcall(socket.new, af.INET, sock.RAW, ipproto.RAW)
    if not (ok_raw and raw_or_err) then
      return nil, raw_or_err
    end
    raw_ip = raw_or_err
    sockets._raw_ip = raw_ip
  end
  local ok_u32, dst_u32 = pcall(string.unpack, ">I4", packet.dst)
  if not (ok_u32 and dst_u32) then
    return nil, "invalid IPv4 destination format"
  end
  local parts, err = split_ipv4_gso_udp(packet.ip_packet, packet.payload)
  if not (parts) then
    return nil, err
  end
  local sent = 0
  for _index_0 = 1, #parts do
    local p = parts[_index_0]
    local ok, ret = pcall(raw_ip.send, raw_ip, p, dst_u32, 0)
    if not (ok and ret and ret > 0) then
      return nil, ret
    end
    sent = sent + 1
  end
  return true, sent
end
local relay_ipv6_with_split
relay_ipv6_with_split = function(sockets, packet)
  local raw_ip6 = sockets._raw_ip6
  if not (raw_ip6) then
    local ok_raw, raw_or_err = pcall(socket.new, af.INET6, sock.RAW, ipproto.UDP)
    if not (ok_raw and raw_or_err) then
      return nil, raw_or_err
    end
    raw_ip6 = raw_or_err
    sockets._raw_ip6 = raw_ip6
  end
  local parts, err = split_ipv6_gso_udp(packet.ip_packet, packet.payload)
  if not (parts) then
    return nil, err
  end
  local sent = 0
  for _index_0 = 1, #parts do
    local udp_pkt = parts[_index_0]
    local ok, ret = send_ipv6_udp(raw_ip6, udp_pkt, packet.dst, packet.dpt, packet.ifindex)
    if not (ok) then
      return nil, ret
    end
    sent = sent + 1
  end
  return true, sent
end
local relay_packet
relay_packet = function(sockets, packet)
  if packet.frame and #packet.frame > 0 then
    local err
    sock, err = get_raw_socket(sockets, packet.ifindex)
    if not (sock) then
      return nil, err
    end
    local ok, sent_or_err = pcall(sock.send, sock, packet.frame)
    if not (ok and sent_or_err and sent_or_err > 0) then
      return nil, sent_or_err
    end
    return true
  end
  if not (packet.ip_packet and #packet.ip_packet > 0) then
    return nil, "missing IP packet bytes"
  end
  if #packet.dst == 4 then
    local ok_u32, dst_u32 = pcall(string.unpack, ">I4", packet.dst)
    if not (ok_u32 and dst_u32) then
      return nil, "invalid IPv4 destination format"
    end
    local raw_ip = sockets._raw_ip
    if not (raw_ip) then
      local ok_raw, raw_or_err = pcall(socket.new, af.INET, sock.RAW, ipproto.RAW)
      if not (ok_raw and raw_or_err) then
        return nil, raw_or_err
      end
      raw_ip = raw_or_err
      sockets._raw_ip = raw_ip
    end
    local ok, sent_or_err = pcall(raw_ip.send, raw_ip, packet.ip_packet, dst_u32, 0)
    if ok and sent_or_err and sent_or_err > 0 then
      return true
    end
    if (not ok) and (tostring(sent_or_err)):find("EMSGSIZE") then
      return relay_ipv4_with_split(sockets, packet)
    end
    return nil, sent_or_err
  end
  if #packet.dst == 16 then
    local raw_ip6 = sockets._raw_ip6
    if not (raw_ip6) then
      local ok_raw, raw_or_err = pcall(socket.new, af.INET6, sock.RAW, ipproto.UDP)
      if not (ok_raw and raw_or_err) then
        return nil, raw_or_err
      end
      raw_ip6 = raw_or_err
      sockets._raw_ip6 = raw_ip6
    end
    if not (#packet.ip_packet >= 48) then
      return nil, "short IPv6 packet for relay"
    end
    local udp_pkt = packet.ip_packet:sub(41)
    local ok, sent_or_err = send_ipv6_udp(raw_ip6, udp_pkt, packet.dst, packet.dpt, packet.ifindex)
    if ok then
      return true
    end
    if (tostring(sent_or_err)):find("EMSGSIZE") or (tostring(sent_or_err)):find("EINVAL") then
      return relay_ipv6_with_split(sockets, packet)
    end
    return nil, sent_or_err
  end
  return nil, "unsupported IP address size " .. tostring(#packet.dst)
end
local extract_initial_packets
extract_initial_packets = function(payload)
  local datagrams, err = QUIC.split_datagrams(payload, 1)
  if not (datagrams) then
    return nil, err
  end
  local packets = { }
  for _index_0 = 1, #datagrams do
    local d = datagrams[_index_0]
    if d.header and d.header.pkt_type == 0x00 then
      packets[#packets + 1] = d.data
    end
  end
  return packets
end
return function()
  local log = logger(cfg.log_level, "snihook/quic", {
    rate_limit_window = cfg.log_rate_limit_window,
    rate_limit_burst = cfg.log_rate_limit_burst
  })
  local env = lunatik._ENV
  local quic_queue = env.snihook_quic_queue
  local quic_event = env.snihook_quic_event
  local whitelist = env.snihook_quic_whitelist
  local quic_verdicts = env.snihook_quic_verdicts
  if not (quic_queue and quic_event and whitelist and quic_verdicts) then
    log.warning("QUIC runtime not configured")
    return 
  end
  local inbox = mailbox.inbox(quic_queue, quic_event)
  local sessions = { }
  local pending_packets = { }
  local raw_sockets = { }
  local session_count = 0
  local backend_error = nil
  local gc = 0
  while not shouldstop() do
    local _continue_0 = false
    repeat
      local ok, msg = pcall(inbox.receive, inbox, 100)
      if not (ok) then
        if not (is_timeout(msg)) then
          log.warning("QUIC inbox receive failed: " .. tostring(msg))
        end
        _continue_0 = true
        break
      end
      log.debug("QUIC inbox received: " .. tostring(#msg))
      if not (msg) then
        _continue_0 = true
        break
      end
      local packet, err = decode_packet(msg)
      if not (packet) then
        log.warning("Discarding malformed QUIC packet message: " .. tostring(err))
        _continue_0 = true
        break
      end
      local id = flow_id(packet.src, packet.spt, packet.dst, packet.dpt)
      local rev = flow_id(packet.dst, packet.dpt, packet.src, packet.spt)
      local conn = canonical_flow(id, rev)
      local pending = pending_packets[conn]
      if not (pending) then
        pending = { }
        pending_packets[conn] = pending
      end
      pending[#pending + 1] = packet
      local verdict = quic_verdicts[id] or quic_verdicts[rev]
      if verdict then
        if verdict > 0 then
          local relayed = 0
          for _index_0 = 1, #pending do
            local queued = pending[_index_0]
            local forwarded, relay_err = relay_packet(raw_sockets, queued)
            if forwarded then
              relayed = relayed + 1
            else
              log.warning("Failed to relay queued QUIC packet: " .. tostring(relay_err))
            end
          end
        end
        pending_packets[conn] = nil
        _continue_0 = true
        break
      end
      local initial_packets, pkt_err = extract_initial_packets(packet.payload)
      if not (initial_packets) then
        log.debug(pkt_err)
        _continue_0 = true
        break
      end
      if not (#initial_packets > 0) then
        _continue_0 = true
        break
      end
      local session = sessions[conn]
      if not (session) then
        if backend_error then
          _continue_0 = true
          break
        end
        local ok_new, session_or_err = pcall(QSession.new)
        if not (ok_new and session_or_err) then
          backend_error = session_or_err
          log.warning("QUIC parser disabled: " .. tostring(session_or_err))
          _continue_0 = true
          break
        end
        session = session_or_err
        sessions[conn] = session
        session_count = session_count + 1
        log.debug("Created QUIC session " .. tostring(conn))
      end
      for _index_0 = 1, #initial_packets do
        local _continue_1 = false
        repeat
          local quic_packet = initial_packets[_index_0]
          local pushed, push_err = session:push(quic_packet)
          if not (pushed) then
            if push_err then
              log.debug("QUIC Initial parse/decrypt pending: " .. tostring(push_err))
            end
            _continue_1 = true
            break
          end
          _continue_1 = true
        until true
        if not _continue_1 then
          break
        end
      end
      local sni = session:sni()
      if not (sni and #sni > 0) then
        log.debug("QUIC SNI not yet available (CRYPTO stream=" .. tostring(#(session:crypto_stream())) .. " bytes)")
        _continue_0 = true
        break
      end
      log.debug("QUIC SNI check: " .. tostring(sni))
      local allowed, reason = check(sni, whitelist)
      verdict = (allowed and 1 or -1) * seconds()
      quic_verdicts[id] = verdict
      quic_verdicts[rev] = verdict
      if allowed and pending then
        local relayed = 0
        for _index_0 = 1, #pending do
          local queued = pending[_index_0]
          local forwarded, relay_err = relay_packet(raw_sockets, queued)
          if forwarded then
            relayed = relayed + 1
          else
            log.warning("Failed to relay queued QUIC packet: " .. tostring(relay_err))
          end
        end
        if relayed > 0 then
          log.debug("Relayed " .. tostring(relayed) .. "/" .. tostring(#pending) .. " queued QUIC packet(s)")
        end
        if relayed > 0 then
          log.debug("QUIC relay flow " .. tostring(IP.ip2s(packet.src)) .. ":" .. tostring(packet.spt) .. " -> " .. tostring(IP.ip2s(packet.dst)) .. ":" .. tostring(packet.dpt))
        end
      end
      pending_packets[conn] = nil
      log[allowed and "info" or "notice"]("QUIC SNI " .. tostring(reason))
      log.debug("QUIC SNI flow " .. tostring(IP.ip2s(packet.src)) .. ":" .. tostring(packet.spt) .. " -> " .. tostring(IP.ip2s(packet.dst)) .. ":" .. tostring(packet.dpt))
      local t = seconds()
      if session_count > 1000 or t - gc > 300 then
        sessions = { }
        pending_packets = { }
        session_count = 0
        gc = t
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  for _, sock in pairs(raw_sockets) do
    pcall(sock.close, sock)
  end
end
