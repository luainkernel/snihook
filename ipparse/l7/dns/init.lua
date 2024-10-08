local subclass, Packet
do
  local _obj_0 = require("ipparse")
  subclass, Packet = _obj_0.subclass, _obj_0.Packet
end
local Question = require("ipparse.l7.dns.question")
local RR = require("ipparse.l7.dns.rr")
local DNS
DNS = subclass(Packet, {
  __name = "DNS",
  iana_port = 53,
  types = (function()
    local t = {
      "A",
      "NS",
      "MD",
      "MF",
      "CNAME",
      "SOA",
      "MB",
      "MG",
      "MR",
      "NULL",
      "WKS",
      "PTR",
      "HINFO",
      "MINFO",
      "MX",
      "TXT",
      "RP",
      "AFSDB",
      "X25",
      "ISDN",
      "RT",
      "NSAP",
      "NSAP-PTR",
      "SIG",
      "KEY",
      "PX",
      "GPOS",
      "AAAA",
      "LOC",
      "NXT",
      "EID",
      "NIMLOC",
      "SRV",
      "ATMA",
      "NAPTR",
      "KX",
      "CERT",
      "A6",
      "DNAME",
      "SINK",
      "OPT",
      "APL",
      "DS",
      "SSHFP",
      "IPSECKEY",
      "RRSIG",
      "NSEC",
      "DNSKEY",
      "DHCID",
      "NSEC3",
      "NSEC3PARAM",
      "TLSA",
      "SMIMEA",
      "HIP",
      "NINFO",
      "RKEY",
      "TALINK",
      "CDS",
      "CDNSKEY",
      "OPENPGPKEY",
      "CSYNC",
      "ZONEMD",
      "SVCB",
      "HTTPS",
      "SPF",
      "EUI48",
      "EUI64",
      "TKEY",
      "TSIG",
      "IXFR",
      "AXFR",
      "MAILB",
      "MAILA",
      "ANY",
      "URI",
      "CAA",
      "AVC",
      "DOA",
      "AMTRELAY",
      "TA",
      "DLV"
    }
    for i = 1, #t do
      t[t[i]] = i
    end
    return t
  end)(),
  _get_id = function(self)
    return self:short(0)
  end,
  _get_qr = function(self)
    return self:bit(2, 1)
  end,
  _get_opcode = function(self)
    return self:byte(2) >> 3 & 0xf
  end,
  _get_aa = function(self)
    return self:bit(2, 6)
  end,
  _get_tc = function(self)
    return self:bit(2, 7)
  end,
  _get_rd = function(self)
    return self:bit(2, 8)
  end,
  _get_ra = function(self)
    return self:bit(3, 1)
  end,
  _get_z = function(self)
    return self:nibble(3) & 0x7
  end,
  _get_rcode = function(self)
    return self:nibble(3, 2)
  end,
  _get_qdcount = function(self)
    return self:short(4)
  end,
  _get_ancount = function(self)
    return self:short(6)
  end,
  _get_nscount = function(self)
    return self:short(8)
  end,
  _get_arcount = function(self)
    return self:short(10)
  end,
  _get_question = function(self)
    return self.questions[1]
  end,
  _get_questions = function(self)
    local questions = { }
    local off = 0
    for i = 1, self.qdcount do
      local q = Question({
        skb = self.skb,
        off = self.off + self.data_off + off
      })
      questions[i] = q
      off = off + q.length
    end
    return questions
  end,
  rrs = function(self, off, count)
    local rrs = { }
    for i = 1, count do
      local r = RR({
        skb = self.skb,
        off = off
      })
      rrs[i] = r
      off = off + r.length
    end
    return rrs
  end,
  _get_answers = function(self)
    local q = self.questions[#self.questions]
    return self:rrs(q.off + q.length, self.ancount)
  end,
  _get_nameservers = function(self)
    local a = self.answers[#self.answers]
    return DNS.rrs(self, a.off + a.length, self.nscount)
  end,
  _get_additional = function(self)
    local ns = self.nameservers[#self.nameservers]
    return DNS.rrs(self, ns.off + ns.length, self.arcount)
  end,
  data_off = 12
})
return DNS
