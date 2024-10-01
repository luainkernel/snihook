local concat
concat = table.concat
local activate, log_level, mode
do
  local _obj_0 = require("snihook.config")
  activate, log_level, mode = _obj_0.activate, _obj_0.log_level, _obj_0.mode
end
local outbox
outbox = require("mailbox").outbox
local register, pfs, hooknum, priority, CONTINUE, DROP
local _exp_0 = mode
if "bridge" == _exp_0 then
  local BRIDGE
  do
    local _obj_0 = require("netfilter")
    register, BRIDGE, hooknum, priority, CONTINUE, DROP = _obj_0.register, _obj_0.family.BRIDGE, _obj_0.bridge_hooks.FORWARD, _obj_0.bridge_priority.FILTER_BRIDGED, _obj_0.action.CONTINUE, _obj_0.action.DROP
  end
  pfs = {
    BRIDGE
  }
elseif "router" == _exp_0 then
  local IPV6, IPV4
  do
    local _obj_0 = require("netfilter")
    register, IPV6, IPV4, hooknum, priority, CONTINUE, DROP = _obj_0.register, _obj_0.family.IPV6, _obj_0.family.IPV4, _obj_0.inet_hooks.FORWARD, _obj_0.ip_priority.FILTER, _obj_0.action.CONTINUE, _obj_0.action.DROP
  end
  pfs = {
    IPV6,
    IPV4
  }
end
DROP = activate and DROP or CONTINUE
require("ipparse")
local IP = require("ipparse.l3.auto_ip")
local Fragmented_IP4 = require("ipparse.l3.fragmented_ip4")
local TCP = require("ipparse.l4.tcp")
local TLS = require("ipparse.l7.tls")
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
local fragmented_ips = setmetatable({ }, {
  __mode = "kv",
  __index = function(self, id)
    self[id] = Fragmented_IP4()
    log.debug(id, self[id])
    return self[id]
  end
})
return function(whitelist, log_queue, log_evt)
  do
    local _with_0 = outbox(log_queue, log_evt)
    log = logger(log_level, "snihook", function(...)
      return _with_0:send(...)
    end)
  end
  local hook
  hook = function(self)
    local ip = IP(self)
    if not ip or ip:is_empty() then
      return CONTINUE
    end
    if ip:is_fragment() then
      log.debug("Fragment detected")
      local f_ip = fragmented_ips[ip.id]:insert(ip)
      if not (f_ip:is_complete()) then
        return CONTINUE
      end
      log.debug("Last fragment received")
      ip = f_ip
      fragmented_ips[ip.id] = nil
    end
    if ip.protocol ~= TCP.protocol_type then
      return CONTINUE
    end
    local tcp = TCP(ip.data)
    if tcp:is_empty() or tcp.dport ~= 443 then
      return CONTINUE
    end
    local tls = TLS(tcp.data)
    if tls:is_empty() or tls.type ~= TLSHandshake.record_type then
      return CONTINUE
    end
    local hshake = TLSHandshake(tls.data)
    if hshake:is_empty() or hshake.type ~= TLSClientHello.message_type then
      return CONTINUE
    end
    local client_hello = TLSClientHello(hshake.data)
    do
      local sni = get_first(client_hello:iter_extensions(), function(self)
        return self.type == SNI.extension_type
      end)
      if sni then
        sni = sni.server_name
        if whitelist[sni] then
          return CONTINUE, log.info(tostring(ip.src) .. " -> " .. tostring(sni) .. " allowed.")
        end
        local sni_parts
        do
          local _accum_0 = { }
          local _len_0 = 1
          for part in sni:gmatch("[^%.]+") do
            _accum_0[_len_0] = part
            _len_0 = _len_0 + 1
          end
          sni_parts = _accum_0
        end
        for i = 2, #sni_parts do
          local domain = concat((function()
            local _accum_0 = { }
            local _len_0 = 1
            for _index_0 = i, #sni_parts do
              local part = sni_parts[_index_0]
              _accum_0[_len_0] = part
              _len_0 = _len_0 + 1
            end
            return _accum_0
          end)(), ".")
          if whitelist[domain] then
            return CONTINUE, log.info(tostring(ip.src) .. " -> " .. tostring(sni) .. " allowed as a subdomain of " .. tostring(domain) .. ".")
          end
        end
        return DROP, log.notice(tostring(ip.src) .. " -> " .. tostring(sni) .. " BLOCKED.")
      end
    end
    return CONTINUE
  end
  for _index_0 = 1, #pfs do
    local pf = pfs[_index_0]
    register({
      pf = pf,
      hooknum = hooknum,
      priority = priority,
      hook = hook
    })
  end
end
