package types

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

type NeighborSolicitMessage struct {
	RouterMac  MacAddr
	RouterAddr IPv6Addr
	DestAddr   IPv6Addr
	TargetAddr IPv6Addr
}

func NewNeighborSolicitMessage(mac, routerAddr, destAddr, targetAddr string) NeighborSolicitMessage {
	routerMac := MacAddr{}
	m, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	if err := routerMac.UnmarshalBinary(m); err != nil {
		panic(err)
	}

	raddr := IPv6Addr{}
	if err := raddr.FromNetipAddr(netip.MustParseAddr(routerAddr)); err != nil {
		panic(err)
	}

	daddr := IPv6Addr{}
	if err := daddr.FromNetipAddr(netip.MustParseAddr(destAddr)); err != nil {
		panic(err)
	}

	taddr := IPv6Addr{}
	if err := taddr.FromNetipAddr(netip.MustParseAddr(targetAddr)); err != nil {
		panic(err)
	}
	return NeighborSolicitMessage{
		RouterMac:  routerMac,
		RouterAddr: raddr,
		DestAddr:   daddr,
		TargetAddr: taddr,
	}
}

func (n NeighborSolicitMessage) String() string {
	return fmt.Sprintf("mac=%s routerAddr=%s destAddr=%s targetAddr=%s",
		net.HardwareAddr(n.RouterMac[:]),
		net.IP(n.RouterAddr[:]),
		net.IP(n.DestAddr[:]),
		net.IP(n.TargetAddr[:]),
	)
}

func (n *NeighborSolicitMessage) UnmarshalBinary(data []byte) error {
	mac := MacAddr{}
	if err := mac.UnmarshalBinary(data[:6]); err != nil {
		return err
	}
	n.RouterMac = mac

	routerAddr := IPv6Addr{}
	if err := routerAddr.UnmarshalBinary(data[6:22]); err != nil {
		return err
	}
	n.RouterAddr = routerAddr

	destAddr := IPv6Addr{}
	if err := destAddr.UnmarshalBinary(data[22:38]); err != nil {
		return err
	}
	n.DestAddr = destAddr

	targetAddr := IPv6Addr{}
	if err := targetAddr.UnmarshalBinary(data[38:54]); err != nil {
		return err
	}
	n.TargetAddr = targetAddr
	return nil
}

type MacAddr [6]byte

func (m *MacAddr) UnmarshalBinary(data []byte) error {
	_, err := binary.Decode(data, binary.BigEndian, m)
	return err
}

func (m *MacAddr) FromNetHardwareAddr(hw net.HardwareAddr) error {
	return m.UnmarshalBinary(hw)
}

type IPv6Addr [16]byte

func (a *IPv6Addr) UnmarshalBinary(data []byte) error {
	_, err := binary.Decode(data, binary.BigEndian, a)
	return err
}

func (a *IPv6Addr) FromNetipAddr(addr netip.Addr) error {
	return a.UnmarshalBinary(addr.AsSlice())
}
