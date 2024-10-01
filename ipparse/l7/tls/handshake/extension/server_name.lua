local subclass
subclass = require("ipparse").subclass
local TLSExtension = require("ipparse.l7.tls.handshake.extension")
return subclass(TLSExtension, {
  __name = "ServerNameIndication",
  extension_type = 0x00,
  type_str = "server name",
  _get_server_name = function(self)
    return self:str(9, self:short(7))
  end
})
