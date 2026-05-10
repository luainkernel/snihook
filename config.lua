return {
  activate = false,
  log_level = "DEBUG",
  log_rate_limit_window = 2,
  log_rate_limit_burst = 1,
  mode = "local",
  filters = {
    "dns",
    "sni",
    "quic"
  },
  quic_mailbox_size = 262144,
  xdp = false,
  netfilter = true
}
