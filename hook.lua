local concat
concat = table.concat
local cfg = require("snihook.config")
local log_level, mode, filters
log_level, mode, filters = cfg.log_level, cfg.mode, cfg.filters
local xdp = require("xdp")
local nf = require("netfilter")
local ntoh16
ntoh16 = require("linux").ntoh16
require("ipparse")
local IP = require("ipparse.l3.auto_ip")
local collect
collect = require("ipparse.l3.fragmented_ip4").collect
local TCP = require("ipparse.l4.tcp")
local UDP = require("ipparse.l4.udp")
local TLS = require("ipparse.l7.tls")
local DNS = require("ipparse.l7.dns")
local TLSHandshake = require("ipparse.l7.tls.handshake")
local TLSClientHello = require("ipparse.l7.tls.handshake.client_hello")
local SNI = require("ipparse.l7.tls.handshake.extension.server_name")
local logger = require("log")
local log
local get_first
get_first = function(self, fn)
  for v in self do
    if fn(v) then
      return v
    end
  end
end
local check
check = function(self, whitelist)
  if whitelist[self] then
    return true, tostring(self) .. " allowed"
  end
  local domain_parts
  do
    local _accum_0 = { }
    local _len_0 = 1
    for part in self:gmatch("[^%.]+") do
      _accum_0[_len_0] = part
      _len_0 = _len_0 + 1
    end
    domain_parts = _accum_0
  end
  for i = 2, #domain_parts do
    local domain = concat((function()
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = i, #domain_parts do
        local part = domain_parts[_index_0]
        _accum_0[_len_0] = part
        _len_0 = _len_0 + 1
      end
      return _accum_0
    end)(), ".")
    if whitelist[domain] then
      return true, tostring(self) .. " allowed as a subdomain of " .. tostring(domain)
    end
  end
  return false, tostring(self) .. " BLOCKED"
end
local filter_sni
filter_sni = function(self, whitelist)
  log.debug("SNI filter " .. tostring(self.protocol == TCP.protocol_type))
  if self.protocol ~= TCP.protocol_type then
    return 
  end
  local tcp = TCP(self.data)
  if tcp:is_empty() or tcp.dport ~= TLS.iana_port then
    return 
  end
  local tls = TLS(tcp.data)
  if tls:is_empty() or tls.type ~= TLSHandshake.record_type then
    return 
  end
  local hshake = TLSHandshake(tls.data)
  if hshake:is_empty() or hshake.type ~= TLSClientHello.message_type then
    return 
  end
  local client_hello = TLSClientHello(hshake.data)
  do
    local sni = get_first(client_hello:iter_extensions(), function(self)
      return self.type == SNI.extension_type
    end)
    if sni then
      sni = sni.server_name
      local ok, msg = check(sni, whitelist)
      return ok, tostring(self.src) .. " -> " .. tostring(msg) .. " (SNI)"
    end
  end
end
local filter_dns
filter_dns = function(self, whitelist)
  local protocol = self.protocol
  log.debug("DNS filter")
  local pkt, is_tcp
  if protocol == UDP.protocol_type then
    pkt = UDP(self.data)
  elseif protocol == TCP.protocol_type and TCP(self.data) then
    pkt = TCP(self.data)
    is_tcp = true
  else
    return 
  end
  log.debug(tostring(pkt.__name) .. " " .. tostring(pkt.sport) .. " " .. tostring(pkt.dport))
  if pkt:is_empty() or (pkt.dport ~= DNS.iana_port and pkt.sport ~= DNS.iana_port) then
    return 
  end
  local dns = DNS(pkt.data)
  if is_tcp then
    dns.off = dns.off + 2
  end
  if dns:is_empty() then
    return 
  end
  do
    local q = dns.question
    if q then
      do
        local domain = q.qname
        if domain then
          if dns.answers then
            local _list_0 = dns.answers
            for _index_0 = 1, #_list_0 do
              local a = _list_0[_index_0]
              log.info("DNS answer type: " .. tostring(DNS.types[a.type]) .. ", rdata: " .. tostring(concat(a.rdata, ',')))
            end
          end
          local ok, msg = check(domain, whitelist)
          return ok, tostring(self.src) .. " -> " .. tostring(self.dst) .. " " .. tostring(msg) .. " (DNS)"
        end
      end
    end
  end
end
local _filters = {
  dns = filter_dns,
  sni = filter_sni
}
return function(whitelist)
  log = logger(log_level, "snihook")
  local report = {
    [true] = log.info,
    [false] = log.notice
  }
  local is_allowed
  is_allowed = function(self)
    if not self or self:is_empty() then
      return true
    end
    log.debug("IP: src " .. tostring(self.src) .. ", dst " .. tostring(self.dst))
    if self:is_fragment() then
      log.debug("Fragment detected")
      local f_ip = collect(self)
      if not (f_ip) then
        return true
      end
      log.debug("Last fragment received")
      self = f_ip
    end
    for _index_0 = 1, #filters do
      local name = filters[_index_0]
      do
        local filter = _filters[name]
        if filter then
          local ok, msg = filter(self, whitelist)
          if ok ~= nil then
            return ok, report[ok](msg)
          end
        else
          log.warning("Unknown filter " .. tostring(name))
        end
      end
    end
    return true
  end
  if cfg.xdp then
    local PASS, DROP
    do
      local _obj_0 = xdp.action
      PASS, DROP = _obj_0.PASS, _obj_0.DROP
    end
    if not cfg.activate then
      DROP = PASS
    end
    xdp.attach(function(skb, arg)
      local off = ntoh16(arg:getuint16(0))
      return is_allowed(IP({
        skb = skb,
        off = off
      })) and PASS or DROP
    end)
  end
  if cfg.netfilter then
    local register, pfs, hooknum, priority, CONTINUE
    local _exp_0 = mode
    if "bridge" == _exp_0 then
      local BRIDGE, DROP
      register, BRIDGE, hooknum, priority, CONTINUE, DROP = nf.register, nf.family.BRIDGE, nf.bridge_hooks.FORWARD, nf.bridge_priority.FILTER_BRIDGED, nf.action.CONTINUE, nf.action.DROP
      pfs = {
        BRIDGE
      }
    elseif "router" == _exp_0 then
      local IPV6, IPV4, DROP
      register, IPV6, IPV4, hooknum, priority, CONTINUE, DROP = nf.register, nf.family.IPV6, nf.family.IPV4, nf.inet_hooks.FORWARD, nf.ip_priority.FILTER, nf.action.CONTINUE, nf.action.DROP
      pfs = {
        IPV6,
        IPV4
      }
    end
    local DROP
    if not cfg.activate then
      DROP = CONTINUE
    end
    for _index_0 = 1, #pfs do
      local pf = pfs[_index_0]
      register({
        pf = pf,
        hooknum = hooknum,
        priority = priority,
        hook = function(skb)
          return is_allowed(IP({
            skb = skb
          })) and CONTINUE or DROP
        end
      })
    end
  end
end
