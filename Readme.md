# Snihook

Snihook is a kernel script that uses the lunatik netfilter library to filter TLS packets.
This script drops any TLS handshake packet forwarded on a bridge with sni not matching the whitelist provided by the user.
This whitelist is populated by the mean of `/dev/sni_whitelist`.

## Installation

Install [lunatik](https://github.com/luainkernel/lunatik).

Install snihook:

```sh
git clone https://github.com/luainkernel/snihook
cd snihook
sudo make install                                              # installs the extension to Xtables directory, and lua files to module directory
```

If one wants to make changes to the code:

```sh
sudo apt install luarocks && sudo luarocks install moonscript  # optional dependency (if one wants to make change to sources)
make                                                           # generates Lua files from MoonScript sources
```

## Usage

```sh
sudo lunatik spawn snihook/main                      # runs the Lua kernel script
echo "add github.com" | sudo tee /dev/sni_whitelist  # opens access to https://github.com (and subdomains of github.com)
echo "del github.com" | sudo tee /dev/sni_whitelist  # removes access to https://github.com (and subdomains not open otherwise)
sudo lunatik stop snihook/main                       # stops the Lua kernel script
```

Note: By default, unallowed domains will get logged (`journalctl -t kernel -g sniblock`), but not blocked.
To effectively block them, set `activate = true` in `/lib/modules/lua/snihook/config.lua`.
