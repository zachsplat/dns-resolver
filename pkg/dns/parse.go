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
}

func ParseResponse(data []byte) (*Response, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	resp := &Response{
		Header: ParseHeader(data),
	}

	offset := 12

	// parse questions
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

	// parse records
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
			if offset+int(rdlen) > len(data) {
				return nil, fmt.Errorf("truncated rdata")
			}
			r.Data = data[offset : offset+int(rdlen)]
			offset += int(rdlen)
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

func FormatRecord(r Record, fullData []byte) string {
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
		name, _ := DecodeName(fullData, -1) // hmm this won't work right
		// actually we need the offset into the full response, not just rdata
		// TODO: fix this, for now just return raw
		_ = name
		return fmt.Sprintf("(raw %d bytes)", len(r.Data))
	}
	return fmt.Sprintf("(raw %d bytes)", len(r.Data))
}
