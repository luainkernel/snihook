:subclass, :Packet = require"ipparse"

subclass Packet, {
  __name: "TLS"

  _get_type: => @byte 0

  _get_version: => "#{@byte 1}.#{@byte 2}"

  _get_length: => @short 3

  data_off: 5
}
