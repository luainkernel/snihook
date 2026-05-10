# Copilot instructions for snihook

## Build and install

- `make` — transpile the MoonScript sources with `moonc .`
- `make install` — install the Lua modules under `/lib/modules/lua/snihook`
- `make xdp.o` — build the XDP helper from `xdp.c`
- `make vmlinux.h` — generate `vmlinux.h` from `/sys/kernel/btf/vmlinux`
- `make clean` — remove `xdp.o` and `vmlinux.h`

To rebuild a single MoonScript source file, run `moonc path/to/file.moon`.

## High-level architecture

Snihook is a kernel-side packet filter for TLS SNI and related traffic. `main.moon` starts two runtimes: `dev.moon` exposes `/dev/sni_whitelist`, and `hook.moon` attaches the packet filters. The whitelist lives in an RCU table and is shared by both runtimes.

`hook.moon` is the policy engine. It loads `snihook.config`, then runs the configured filter chain (`dns`, `sni`, `quic`) over forwarded packets. Each filter can short-circuit with allow/block and emits logs through `snihook.log`. The netfilter path supports `bridge`, `router`, and `local` modes; the XDP path uses `xdp.attach` when enabled.

`dev.moon` is the control surface. It uses `device.new` to create the whitelist device, returns the current whitelist as a sorted comma-separated line, and accepts `+ DOMAIN` / `- DOMAIN` updates.

## Conventions

- Treat the `.moon` files as the source of truth; keep the generated `.lua` files in sync.
- Config defaults live in `config.moon`: `activate = false`, `log_level = "DEBUG"`, `mode = "local"`, `filters = {"dns", "sni", "quic"}`, `xdp = false`, `netfilter = true`.
- Preserve the whitelist command format used by `/dev/sni_whitelist`.
- Keep filter behavior order-sensitive: DNS, SNI, and QUIC are separate fast paths, and unknown filter names only log a warning.
- XDP helper generation depends on the running kernel BTF data; the helper target is `xdp.o`, not a generic object directory.
