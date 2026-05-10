{
  activate: false       -- If false, unallowed domains will be logged, but not blocked.
  log_level: "DEBUG"    -- Same as syslog severity level
  log_rate_limit_window: 2  -- seconds
  log_rate_limit_burst: 1   -- max identical lines per window
  mode: "local"         -- "bridge", "router", "local"
  filters: {"dns", "sni", "quic"}
  quic_mailbox_size: 262144
  xdp: false
  netfilter: true
}
