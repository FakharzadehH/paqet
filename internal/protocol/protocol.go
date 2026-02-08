package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"paqet/internal/conf"
	"paqet/internal/tnet"
)

type PType = byte

const (
	PPING PType = 0x01
	PPONG PType = 0x02
	PTCPF PType = 0x03
	PTCP  PType = 0x04
	PUDP  PType = 0x05
)

type Proto struct {
	Type PType
	Addr *tnet.Addr
	TCPF []conf.TCPF
}

func (p *Proto) Write(w io.Writer) error {
	// Write type byte
	if _, err := w.Write([]byte{p.Type}); err != nil {
		return err
	}

	// Write address (length-prefixed string)
	addrStr := ""
	if p.Addr != nil {
		addrStr = p.Addr.String()
	}
	addrBytes := []byte(addrStr)
	if err := binary.Write(w, binary.BigEndian, uint16(len(addrBytes))); err != nil {
		return err
	}
	if len(addrBytes) > 0 {
		if _, err := w.Write(addrBytes); err != nil {
			return err
		}
	}

	// Write TCPF count and entries
	if err := binary.Write(w, binary.BigEndian, uint16(len(p.TCPF))); err != nil {
		return err
	}
	for _, f := range p.TCPF {
		flags := encodeTCPF(f)
		if err := binary.Write(w, binary.BigEndian, flags); err != nil {
			return err
		}
	}

	return nil
}

func (p *Proto) Read(r io.Reader) error {
	// Read type byte
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, typeBuf); err != nil {
		return err
	}
	p.Type = typeBuf[0]

	// Read address
	var addrLen uint16
	if err := binary.Read(r, binary.BigEndian, &addrLen); err != nil {
		return err
	}
	if addrLen > 0 {
		addrBytes := make([]byte, addrLen)
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return err
		}
		addr, err := tnet.NewAddr(string(addrBytes))
		if err != nil {
			return fmt.Errorf("invalid address: %w", err)
		}
		p.Addr = addr
	}

	// Read TCPF entries
	var tcpfCount uint16
	if err := binary.Read(r, binary.BigEndian, &tcpfCount); err != nil {
		return err
	}
	if tcpfCount > 0 {
		p.TCPF = make([]conf.TCPF, tcpfCount)
		for i := uint16(0); i < tcpfCount; i++ {
			var flags uint16
			if err := binary.Read(r, binary.BigEndian, &flags); err != nil {
				return err
			}
			p.TCPF[i] = decodeTCPF(flags)
		}
	}

	return nil
}

func encodeTCPF(f conf.TCPF) uint16 {
	var flags uint16
	if f.FIN {
		flags |= 1 << 0
	}
	if f.SYN {
		flags |= 1 << 1
	}
	if f.RST {
		flags |= 1 << 2
	}
	if f.PSH {
		flags |= 1 << 3
	}
	if f.ACK {
		flags |= 1 << 4
	}
	if f.URG {
		flags |= 1 << 5
	}
	if f.ECE {
		flags |= 1 << 6
	}
	if f.CWR {
		flags |= 1 << 7
	}
	if f.NS {
		flags |= 1 << 8
	}
	return flags
}

func decodeTCPF(flags uint16) conf.TCPF {
	return conf.TCPF{
		FIN: flags&(1<<0) != 0,
		SYN: flags&(1<<1) != 0,
		RST: flags&(1<<2) != 0,
		PSH: flags&(1<<3) != 0,
		ACK: flags&(1<<4) != 0,
		URG: flags&(1<<5) != 0,
		ECE: flags&(1<<6) != 0,
		CWR: flags&(1<<7) != 0,
		NS:  flags&(1<<8) != 0,
	}
}
