package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type Record struct {
	Name        string
	Type        uint16
	Class       uint16
	TTL         uint32
	Data        []byte
	DecodedName string
}

const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeAAAA  = 28
	ClassIN   = 1
)

func (h *Header) Marshal() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:], h.ID)
	binary.BigEndian.PutUint16(buf[2:], h.Flags)
	binary.BigEndian.PutUint16(buf[4:], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:], h.ANCount)
	binary.BigEndian.PutUint16(buf[8:], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:], h.ARCount)
	return buf
}

func ParseHeader(data []byte) Header {
	return Header{
		ID:      binary.BigEndian.Uint16(data[0:]),
		Flags:   binary.BigEndian.Uint16(data[2:]),
		QDCount: binary.BigEndian.Uint16(data[4:]),
		ANCount: binary.BigEndian.Uint16(data[6:]),
		NSCount: binary.BigEndian.Uint16(data[8:]),
		ARCount: binary.BigEndian.Uint16(data[10:]),
	}
}

func EncodeName(name string) []byte {
	var buf []byte
	for _, p := range strings.Split(name, ".") {
		if len(p) == 0 {
			continue
		}
		buf = append(buf, byte(len(p)))
		buf = append(buf, []byte(p)...)
	}
	buf = append(buf, 0)
	return buf
}

func DecodeName(data []byte, offset int) (string, int) {
	var parts []string
	jumped := false
	origOffset := offset

	for {
		if offset >= len(data) {
			break
		}
		length := int(data[offset])
		if length == 0 {
			if !jumped {
				origOffset = offset + 1
			}
			break
		}
		if length&0xC0 == 0xC0 {
			if !jumped {
				origOffset = offset + 2
			}
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2])) & 0x3FFF
			offset = pointer
			jumped = true
			continue
		}
		offset++
		if offset+length > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(parts, "."), origOffset
}

func BuildQuery(name string, qtype uint16) []byte {
	hdr := Header{
		ID:      randID(),
		Flags:   0x0100,
		QDCount: 1,
	}
	var buf []byte
	buf = append(buf, hdr.Marshal()...)
	buf = append(buf, EncodeName(name)...)
	qb := make([]byte, 4)
	binary.BigEndian.PutUint16(qb[0:], qtype)
	binary.BigEndian.PutUint16(qb[2:], ClassIN)
	buf = append(buf, qb...)
	return buf
}

func TypeString(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeAAAA:
		return "AAAA"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}
