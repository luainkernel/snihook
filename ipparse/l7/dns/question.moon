:subclass, :Packet = require"ipparse"
:concat, :unpack = table

subclass Packet, {
  __name: "DNSQuestion"

  _get_labels_offsets: =>
    offsets = {}
    pos = 0
    for i = 1, 1000
      size = @byte pos
      break if size == 0
      pos += 1
      offsets[i] = {pos, size >= 192 and 1 or size}
      --TODO implement DNS compression
      break if size >= 192
      pos += size
    offsets

  _get_labels: =>
    labels = {}
    offs = @labels_offsets
    for i = 1, #offs
      labels[#labels+1] = @str unpack offs[i]
    labels

  _get_qtype_offset: =>
    offs = @labels_offsets
    {pos, size} = offs[#offs]
    pos + size + 1

  _get_qtype: => @short @qtype_offset

  _get_qclass: => @short @qtype_offset+2

  _get_qname: => concat @labels, "."

  _get_length: => @qtype_offset + 4
}

