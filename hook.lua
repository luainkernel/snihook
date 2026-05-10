local concat = table.concat
local cfg = require("snihook.config")
local xdp = require("xdp")
local xdp_action = require("linux.xdp")
local register
register = require("netfilter").register
local action, inet, proto, pri
do
  local _obj_0 = require("linux.nf")
  action, inet, proto, pri = _obj_0.action, _obj_0.inet, _obj_0.proto, _obj_0.ip.pri
end
local ntoh16, time
do
  local _obj_0 = require("linux")
  ntoh16, time = _obj_0.ntoh16, _obj_0.time
end
local range, wrap
do
  local _obj_0 = require("ipparse.fun")
  range, wrap = _obj_0.range, _obj_0.wrap
end
require("ipparse")
local IP = require("ipparse.l3.ip")
local collect
collect = require("ipparse.l3.fragmented_ip4").collect
local TCP = require("ipparse.l4.tcp")
local UDP = require("ipparse.l4.udp")
local QUIC = require("ipparse.l4.quic")
local TLS = require("ipparse.l7.tls")
local DNS = require("ipparse.l7.dns")
local TLSHandshake = require("ipparse.l7.tls.handshake")
local TLSClientHello = require("ipparse.l7.tls.handshake.client_hello")
local SNI = require("ipparse.l7.tls.handshake.extension.server_name")
local mailbox = require("mailbox")
local map
map = require("rcu").map
local logger = require("snihook.log")
local log
local get_first
get_first = function(self, fn)
  for v in self do
    if fn(v) then
      return v
    end
  end
end
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
local allowed_tls = { }
local quic_pending = { }
local quic_outbox
local quic_verdicts
local flow_id
flow_id = function(src, spt, dst, dpt)
  return tostring(IP.ip2s(src)) .. ":" .. tostring(spt) .. ">" .. tostring(IP.ip2s(dst)) .. ":" .. tostring(dpt)
end
local filter_sni
filter_sni = function(self, ip, whitelist)
  local pkt = self
  if not (ip.protocol == IP.proto.TCP) then
    return 
  end
  local tcp = TCP.parse(pkt, ip.data_off)
  if not (tcp) then
    return 
  end
  local id = flow_id(ip.src, tcp.spt, ip.dst, tcp.dpt)
  local rev = flow_id(ip.dst, tcp.dpt, ip.src, tcp.spt)
  if allowed_tls[id] or allowed_tls[rev] then
    local now = seconds()
    allowed_tls[id] = now
    allowed_tls[rev] = now
    if log then
      log.debug("TLS cache hit for flow " .. tostring(id))
    end
    return true, nil
  end
  if not (tcp.dpt == 443) then
    return 
  end
  if not (tcp.data_off and tcp.data_off <= #pkt) then
    return 
  end
  if not ((#pkt - tcp.data_off + 1) >= 5) then
    return 
  end
  local parsed, verdict, msg = pcall(function()
    local tls = TLS.parse(pkt, tcp.data_off)
    if not (tls and tls.type == TLS.record_types.handshake) then
      return 
    end
    local hs, hs_off = TLSHandshake.parse(pkt, tls.data_off)
    if not (hs and hs.type == TLSHandshake.message_types.client_hello) then
      return 
    end
    local ch = TLSClientHello.parse(pkt, hs_off)
    if not (ch and ch.extensions and #ch.extensions > 0) then
      return 
    end
    for ext in TLSHandshake.iter_extensions(ch.extensions) do
      local _continue_0 = false
      repeat
        do
          if not (ext and ext.type == TLSHandshake.extensions.server_name) then
            _continue_0 = true
            break
          end
          local sni = SNI.parse(ext.data)
          if not (sni and sni.name and #sni.name > 0) then
            _continue_0 = true
            break
          end
          if log then
            log.debug("TLS ClientHello SNI=" .. tostring(sni.name))
          end
          local ok, reason = check(sni.name, whitelist)
          if ok then
            local now = seconds()
            allowed_tls[id] = now
            allowed_tls[rev] = now
          end
          return ok, "TLS SNI " .. tostring(reason)
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
  end)
  if not (parsed) then
    if log then
      log.debug("TLS parse error on flow " .. tostring(id) .. ": " .. tostring(verdict))
    end
    return 
  end
  return verdict, msg
end
local filter_dns
filter_dns = function(self, ip, whitelist)
  local pkt = self
  if not (ip.protocol == IP.proto.UDP) then
    return 
  end
  local udp = UDP.parse(pkt, ip.data_off)
  if not (udp and udp.dpt == 53) then
    return 
  end
  local parsed, dns = pcall(DNS.parse, pkt, udp.data_off, false)
  if not (parsed) then
    if log then
      log.debug("DNS parse error on UDP " .. tostring(udp.spt) .. "->" .. tostring(udp.dpt) .. ": " .. tostring(dns))
    end
    return 
  end
  if not (dns and dns.question and dns.question.name and #dns.question.name > 0) then
    return 
  end
  if log then
    log.debug("DNS query for " .. tostring(dns.question.name))
  end
  local ok, reason = check(dns.question.name, whitelist)
  return ok, "DNS " .. tostring(reason)
end
local maybe_quic_initial
maybe_quic_initial = function(payload)
  if not (payload and #payload > 0) then
    return false
  end
  local parsed, q = pcall(QUIC.parse, payload)
  if not (parsed and q and q.long_header) then
    return false
  end
  return q.pkt_type == 0x00
end
local filter_quic
filter_quic = function(self, ip, whitelist, skb)
  if skb == nil then
    skb = nil
  end
  local pkt = self
  if not (ip.protocol == IP.proto.UDP) then
    return 
  end
  local udp = UDP.parse(pkt, ip.data_off)
  if not (udp and (udp.dpt == 443 or udp.spt == 443)) then
    return 
  end
  local id = flow_id(ip.src, udp.spt, ip.dst, udp.dpt)
  local rev = flow_id(ip.dst, udp.dpt, ip.src, udp.spt)
  local verdict = quic_verdicts and (quic_verdicts[id] or quic_verdicts[rev])
  if verdict then
    quic_pending[id] = nil
    quic_pending[rev] = nil
    if verdict > 0 then
      return true, nil
    end
    return false, nil
  end
  local payload = pkt:sub(udp.data_off)
  if not (#payload > 0) then
    return 
  end
  local t = seconds()
  local pending = quic_pending[id] or quic_pending[rev]
  local initial = maybe_quic_initial(payload)
  if not (quic_outbox) then
    if log then
      log.warning("QUIC parser runtime unavailable, dropping UDP/443 flow")
    end
    return false, nil
  end
  if not (pending or initial) then
    if log then
      log.debug("QUIC non-initial flow allowed (not pending) for flow " .. tostring(id))
    end
    return true, nil
  end
  if pending and not initial then
    return false, nil
  end
  local ifindex = 0
  local frame = ""
  if skb then
    local ok_if, v_if = pcall(skb.ifindex, skb)
    if ok_if and v_if then
      ifindex = v_if
    end
    local ok_frame, v_frame = pcall((function()
      return skb:data("mac"):getstring(0)
    end))
    if ok_frame and v_frame then
      frame = v_frame
    end
  end
  local msg = string.pack(">s2H s2H s4 I4 s4 s4", ip.src, udp.spt, ip.dst, udp.dpt, payload, ifindex, frame, pkt)
  local sent, err = pcall(quic_outbox.send, quic_outbox, msg)
  if not (sent) then
    if log then
      log.warning("QUIC packet enqueue failed: " .. tostring(err))
    end
    quic_pending[id] = t
    quic_pending[rev] = t
    return false, nil
  end
  quic_pending[id] = t
  quic_pending[rev] = t
  if not (pending) then
    if log then
      log.debug("QUIC flow pending inspection (dropped fail-closed): " .. tostring(IP.ip2s(ip.src)) .. ":" .. tostring(udp.spt) .. " -> " .. tostring(IP.ip2s(ip.dst)) .. ":" .. tostring(udp.dpt))
    end
  end
  if log then
    log.debug("Queued UDP/443 packet for QUIC parser (" .. tostring(IP.ip2s(ip.src)) .. ":" .. tostring(udp.spt) .. " -> " .. tostring(IP.ip2s(ip.dst)) .. ":" .. tostring(udp.dpt) .. ")")
  end
  return false, nil
end
local _filters = {
  dns = filter_dns,
  sni = filter_sni,
  quic = filter_quic
}
return function(whitelist, quic_queue, quic_event, _quic_verdicts)
  if quic_queue == nil then
    quic_queue = nil
  end
  if quic_event == nil then
    quic_event = nil
  end
  if _quic_verdicts == nil then
    _quic_verdicts = nil
  end
  log = logger(cfg.log_level, "snihook", {
    rate_limit_window = cfg.log_rate_limit_window,
    rate_limit_burst = cfg.log_rate_limit_burst
  })
  quic_verdicts = _quic_verdicts
  if quic_queue and quic_event then
    quic_outbox = mailbox.outbox(quic_queue, quic_event)
  else
    log.warning("QUIC outbox not configured; QUIC flows will be dropped fail-closed")
  end
  local filters = cfg.filters
  local report = {
    [true] = log.info,
    [false] = log.notice
  }
  local gc = 0
  local is_allowed
  is_allowed = function(pkt, skb)
    if skb == nil then
      skb = nil
    end
    if not pkt then
      return true
    end
    local ip = IP.parse(pkt)
    log.debug("IP: src " .. tostring(IP.ip2s(ip.src)) .. ", dst " .. tostring(IP.ip2s(ip.dst)))
    for _, name in ipairs(filters) do
      do
        local filter = _filters[name]
        if filter then
          local ok, msg = filter(pkt, ip, whitelist, skb)
          if ok ~= nil then
            if msg then
              report[ok](msg)
            end
            return ok, msg
          end
        else
          log.warning("Unknown filter " .. tostring(name))
        end
      end
    end
    local t = seconds()
    if t - gc > 60 then
      for k, v in pairs(allowed_tls) do
        if t - v > 86400 then
          allowed_tls[k] = nil
        end
      end
      if quic_verdicts then
        map(quic_verdicts, function(self)
          local k = self
          local v = quic_verdicts[k]
          if v and t - math.abs(v) > 300 then
            quic_verdicts[k] = nil
          end
        end)
      end
      for k, v in pairs(quic_pending) do
        if t - v > 10 then
          quic_pending[k] = nil
        end
      end
      gc = t
    end
    local l4_port = nil
    local _exp_0 = ip.protocol
    if IP.proto.UDP == _exp_0 then
      local udp = UDP.parse(pkt, ip.data_off)
      if udp then
        l4_port = udp.dpt
      end
    elseif IP.proto.TCP == _exp_0 then
      local tcp = TCP.parse(pkt, ip.data_off)
      if tcp then
        l4_port = tcp.dpt
      end
    end
    log.debug(tostring(IP.ip2s(ip.src)) .. " -> " .. tostring(IP.ip2s(ip.dst)) .. " (" .. tostring((IP.proto[ip.protocol] or ip.protocol)) .. " " .. tostring(l4_port or '?') .. ") allowed")
    return true, nil
  end
  if cfg.xdp then
    local DROP = cfg.activate and xdp_action.DROP or xdp_action.PASS
    local PASS = xdp_action.PASS
    log.debug("XDP: activate=" .. tostring(cfg.activate) .. " DROP=" .. tostring(DROP) .. " PASS=" .. tostring(PASS))
    xdp.attach(function(self)
      local pkt = self:data("net"):getstring(0)
      return is_allowed(pkt, nil) and PASS or DROP
    end)
  end
  if cfg.netfilter then
    local DROP = cfg.activate and action.DROP or action.ACCEPT
    local ACCEPT = action.ACCEPT
    log.debug("Netfilter: activate=" .. tostring(cfg.activate) .. " DROP=" .. tostring(DROP) .. " ACCEPT=" .. tostring(ACCEPT))
    local pfs = { }
    local hooknum = inet.FORWARD
    local priority = pri.FILTER
    local _exp_0 = cfg.mode
    if "bridge" == _exp_0 then
      pfs = {
        proto.BRIDGE
      }
      priority = pri.FILTER_BRIDGED
    elseif "router" == _exp_0 then
      pfs = {
        proto.IPV4,
        proto.IPV6
      }
    elseif "local" == _exp_0 then
      pfs = {
        proto.INET
      }
      hooknum = inet.POST_ROUTING
    end
    for _index_0 = 1, #pfs do
      local pf = pfs[_index_0]
      register({
        pf = pf,
        hooknum = hooknum,
        priority = priority,
        hook = function(self)
          local pkt = self:data("net"):getstring(0)
          return is_allowed(pkt, self) and ACCEPT or DROP
        end
      })
    end
  end
end
