return {
  activate = false,
  log_level = "NOTICE",
  mode = "bridge",
  filters = {
    "dns",
    "sni"
  },
  xdp = true,
  netfilter = false
}
