:concat = table

:inbox = require"mailbox"
:activate, :log_level, :mode = require"snihook.config"
local register, pfs, hooknum, priority, CONTINUE, DROP
switch mode
  when "bridge"
    :register, family: {:BRIDGE}, bridge_hooks: {FORWARD: hooknum}, bridge_priority: {FILTER_BRIDGED: priority}, action: {:CONTINUE, :DROP} = require"netfilter"
    pfs = {BRIDGE}
  when "router"
    :register, family: {:IPV6, :IPV4}, inet_hooks: {FORWARD: hooknum}, ip_priority: {FILTER: priority}, action: {:CONTINUE, :DROP} = require"netfilter"
    pfs = {IPV6, IPV4}
DROP = activate and DROP or CONTINUE
:set_log, :notice, :info, :dbg = require"snihook.log"
:auto_ip, IP: {protocols: {TCP: tcp_proto}}, :Fragmented_IP4, :TCP, :TLS, :TLSHandshake, :TLSExtension = require"snihook.ipparse"
:handshake = TLS.types
:hello = TLSHandshake.types
:server_name = TLSExtension.types

get_first = (fn) =>  -- Returns first value of an iterator that matches the condition defined in function fn.
  for v in @
    return v if fn v

fragmented_ips = setmetatable {},  __mode: "kv", __index: (id) =>
  @[id] = Fragmented_IP4!
  dbg id, @[id]
  @[id]


(whitelist, log_queue, log_evt) ->
  set_log log_queue, log_evt, log_level, "snihook"

  hook = =>
    ip = auto_ip @
    return CONTINUE if not ip or ip\is_empty!
    if ip\is_fragment!
      dbg"Fragment detected"
      f_ip = fragmented_ips[ip.id]\insert(ip)
      return CONTINUE unless f_ip\is_complete!
      dbg"Last fragment received"
      ip = f_ip
      fragmented_ips[ip.id] = nil
    return CONTINUE if ip.protocol ~= tcp_proto

    tcp = TCP ip.data
    return CONTINUE if tcp\is_empty! or tcp.dport ~= 443

    tls = TLS tcp.data
    return CONTINUE if tls\is_empty! or tls.type ~= handshake

    hshake = TLSHandshake tls.data
    return CONTINUE if hshake\is_empty! or hshake.type ~= hello

    if sni = get_first hshake\iter_extensions!, => @type == server_name
      sni = sni.server_name
      if whitelist[sni]
        return CONTINUE, info"#{ip.src} -> #{sni} allowed."
      sni_parts = [ part for part in sni\gmatch"[^%.]+" ]
      for i = 2, #sni_parts
        domain = concat [ part for part in *sni_parts[i,] ], "."
        if whitelist[domain]
          return CONTINUE, info"#{ip.src} -> #{sni} allowed as a subdomain of #{domain}."
      return DROP, notice"#{ip.src} -> #{sni} BLOCKED."

    CONTINUE


  register :pf, :hooknum, :priority, :hook for pf in *pfs
