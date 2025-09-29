package dns

import (
	"encoding/binary"
	"fmt"
	"net"
)

type Response struct {
	Header    Header
	Questions []Question
	Answers   []Record
	Authority []Record
	Extra     []Record
	raw       []byte // keep raw bytes for name decompression
}

func ParseResponse(data []byte) (*Response, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	resp := &Response{
		Header: ParseHeader(data),
		raw:    data,
	}

	offset := 12

	for i := 0; i < int(resp.Header.QDCount); i++ {
		name, newOff := DecodeName(data, offset)
		offset = newOff
		if offset+4 > len(data) {
			return nil, fmt.Errorf("truncated question")
		}
		q := Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset:]),
			Class: binary.BigEndian.Uint16(data[offset+2:]),
		}
		offset += 4
		resp.Questions = append(resp.Questions, q)
	}

	parseRecords := func(count int) ([]Record, error) {
		var records []Record
		for i := 0; i < count; i++ {
			name, newOff := DecodeName(data, offset)
			offset = newOff
			if offset+10 > len(data) {
				return nil, fmt.Errorf("truncated record")
			}
			r := Record{
				Name:  name,
				Type:  binary.BigEndian.Uint16(data[offset:]),
				Class: binary.BigEndian.Uint16(data[offset+2:]),
				TTL:   binary.BigEndian.Uint32(data[offset+4:]),
			}
			rdlen := binary.BigEndian.Uint16(data[offset+8:])
			offset += 10

			rdataStart := offset
			if offset+int(rdlen) > len(data) {
				return nil, fmt.Errorf("truncated rdata")
			}
			r.Data = data[offset : offset+int(rdlen)]
			offset += int(rdlen)

			// decode name-based rdata types using the full response
			switch r.Type {
			case TypeCNAME, TypeNS:
				decoded, _ := DecodeName(data, rdataStart)
				r.DecodedName = decoded
			}

			records = append(records, r)
		}
		return records, nil
	}

	var err error
	resp.Answers, err = parseRecords(int(resp.Header.ANCount))
	if err != nil {
		return nil, err
	}
	resp.Authority, err = parseRecords(int(resp.Header.NSCount))
	if err != nil {
		return nil, err
	}
	resp.Extra, err = parseRecords(int(resp.Header.ARCount))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func FormatRecord(r Record) string {
	switch r.Type {
	case TypeA:
		if len(r.Data) == 4 {
			return net.IP(r.Data).String()
		}
	case TypeAAAA:
		if len(r.Data) == 16 {
			return net.IP(r.Data).String()
		}
	case TypeCNAME, TypeNS:
		if r.DecodedName != "" {
			return r.DecodedName
		}
	}
	return fmt.Sprintf("(%d bytes)", len(r.Data))
}
