{
  activate: false       -- If false, unallowed domains will be logged, but not blocked.
  log_level: "NOTICE"   -- Same as syslog severity level
  mode: "bridge"        -- "bridge" or "router"
  filters: {"dns", "sni"}
  xdp: true
  netfilter: false
}

