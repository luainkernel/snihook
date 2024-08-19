:concat = table
:min = math
:wrap, :yield = coroutine

:ntoh16, :ntoh32 = require"linux"
log = require"snihook.log"


Object = {
  __name: "Object"
  new: (obj) =>
    cls = @ ~= obj and @ or nil
    setmetatable obj, {
      __index: (k) =>
        if getter = rawget(@, "_get_#{k}") or cls and cls["_get_#{k}"]
          log.dbg "get #{@__name} #{k}"
          @k = getter @
          log.dbg "#{@k}"
          @k
        else if cls
          cls[k]
      __call: (...) => obj\new ...
    }
}
Object.new Object, Object
subclass = Object.new


Packet = subclass Object, {
  __name: "Packet"
  new: (obj) =>
    assert obj.skb, "I need a skb to parse"
    obj.off or= 0
    Object.new @, obj

  bit: (offset, n = 1) =>
    if log.level == 7
      ok, ret = pcall @skb.getbyte, @skb, @off+offset
      ((ret >> (8-n)) & 1) if ok else log.error @__name, "bit", ret, "#{@off} #{offset} #{#@skb}"
    else
      (@skb\getbyte(@off+offset) >> n) & 1

  nibble: (offset, half = 0) =>
    if log.level == 7
      ok, ret = pcall @skb.getbyte, @skb, @off+offset
      (half == 0 and ret >> 4 or ret & 0xf) if ok else log.error @__name, "nibble", "#{@off} #{offset} #{#@skb}"
    else
      b = @skb\getbyte @off+offset
      half == 0 and b >> 4 or b & 0xf

  byte: (offset) =>
    if log.level == 7
      ok, ret = pcall @skb.getbyte, @skb, @off+offset
      ret if ok else log.error @__name, "byte", ret, "#{@off} #{offset} #{#@skb}"
    else
      @skb\getbyte @off+offset

  short: (offset) =>
    if log.level == 7
      ok, ret = pcall @skb.getuint16, @skb, @off+offset
      ntoh16(ret) if ok else log.error @__name, "short", ret, "#{@off} #{offset} #{#@skb}"
    else
      ntoh16 @skb\getuint16 @off+offset

  long: (offset) =>
    if log.level == 7
      ok, ret = pcall @skb.getuint32, @skb, @off+offset
      ntoh32(ret) if ok else log.error @__name, "long", ret, "#{@off} #{offset} #{#@skb}"
    else
      ntoh32 @skb\getuint32 @off+offset

  str: (offset=0, length=#@skb-@off) =>
    off = @off + offset
    if off + length > #@skb
      length = #@skb - off
      log.info"Fragmented packet. Probable incomplete data."
    if log.level == 7
      ok, ret = pcall @skb.getstring, @skb, @off+offset, length
      ret if ok else log.error @__name, "str", ret, "#{@off} #{offset} #{length} #{#@skb}"
    else
      @skb\getstring @off+offset, length

  is_empty: => @off >= #@skb

  _get_data: => skb: @skb, off: @off + @data_off
}


IP = subclass Packet, {
  __name: "IP"
  
  _get_version: => @nibble 0
  
  protocols: {
    TCP:    0x06
    UDP:    0x11
    GRE:    0x2F
    ESP:    0x32
    ICMPv6: 0x3A
    OSPF:   0x59
  }
}


IP4 = subclass IP, {
  __name: "IP4"

  get_ip_at: (off) => concat [ "%d"\format(@byte i) for i = off, off+3 ], "."

  _get_length: => @short 2

  _get_protocol: => @byte 9

  _get_src: => @get_ip_at 12

  _get_dst: => @get_ip_at 16

  _get_data_off: => 4 * @nibble 0, 1
}


IP6 = subclass IP, {
  __name: "IP6"
  
  get_ip_at: (off) => concat [ "%x"\format(@short i) for i = off, off+14, 2 ], ":"

  _get_length: => @data_off + @short 4

  _get_next_header: => @byte 6

  _get_protocol: => @next_header

  _get_src: => @get_ip_at 8

  _get_dst: => @get_ip_at 24

  _get_data_off: => 40
}


auto_ip = =>
  ip = IP skb: @
  switch ip.version
    when 4
      IP4 skb: @
    when 6
      IP6 skb: @


TCP = subclass Packet, {
  __name: "TCP"
  
  _get_sport: => @short 0
  
  _get_dport: => @short 2

  _get_sequence_number: => @long 4

  _get_acknowledgment_number: => @long 8

  _get_data_off: => 4 * @nibble 12

  _get_URG: => @bit 13, 3

  _get_ACK: => @bit 13, 4
  
  _get_PSH: => @bit 13, 5

  _get_RST: => @bit 13, 6

  _get_SYN: => @bit 13, 7

  _get_FIN: => @bit 13, 8

  _get_window: => @short 14

  _get_checksum: => @short 16

  _get_urgent_pointer: => @short 18
}


TLS = subclass Packet, {
  __name: "TLS"
  
  _get_type: => @byte 0
  
  _get_version: => "#{@byte 1}.#{@byte 2}"
  
  _get_length: => @short 3
  
  _get_data_off: => 5

  types: {
    handshake: 0x16
  }
}


TLSExtension = subclass Packet, {
  __name: "TLSExtension"
  
  _get_type: => @short 0
  
  _get_length: => 4 + @short 2

  types: {
    server_name: 0x00
  }
}


TLS_extensions = setmetatable {
  [0x00]: subclass TLSExtension, {
    __name: "ServerNameIndication"
    
    _get_type_str: => "server name"
  
    _get_server_name: => @str 9, @short 7
  }
}, __index: (k) => subclass TLSExtension, {
  __name: "UnknownTlsExtension"
  
  _get_type_str: => "unknown"
}


TLSHandshake = subclass Packet, {
  __name: "TLSHandshake"
  
  _get_type: => @byte 0
  
  _get_length: => @byte(1) << 16 | @short 2
  
  _get_client_version: => "#{@byte 4}.#{@byte 5}"
  
  _get_client_random: => @str 6, 32
  
  _get_session_id_length: => @byte 38
  
  _get_session_id: => @str 39, @session_id_length
  
  _get_ciphers_offset: => 39 + @session_id_length
  
  _get_ciphers_length: => @short @ciphers_offset
  
  _get_ciphers: => [ @short(@ciphers_offset + 2 + i) for i = 0, @ciphers_length-2, 2 ]
  
  _get_compressions_offset: => @ciphers_offset + 2 + @ciphers_length
  
  _get_compressions_length: => @byte @compressions_offset
  
  _get_compressions: => [ @byte(@compressions_offset + 1 + i) for i = 0, @compressions_length - 1 ]
  
  _get_extensions_offset: => @compressions_offset + 1 + @compressions_length
  
  _get_extensions: => [ extension for extension in @iter_extensions! ]

  iter_extensions: => wrap ->
    offset = @extensions_offset + 2
    max_offset = min #@skb-@off-6, offset + @short @extensions_offset
    while offset < max_offset
      extension = TLS_extensions[@short offset] skb: @skb, off: @off + offset
      yield extension
      offset += extension.length

  types: {
    hello: 0x01
  }
}


{
  :log,
  :Object, :subclass,
  :Packet, :IP, :IP4, :IP6, :auto_ip,
  :TCP,
  :TLS, :TLSExtension, :TLSHandshake, :TLS_extensions
}

