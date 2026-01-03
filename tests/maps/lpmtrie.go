package maps

import (
	"errors"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/hown3d/nassauer/tests/types"
)

type LPMTrie struct {
	m *ebpf.Map
}

type key struct {
	PrefixLen uint32
	Addr      types.IPv6Addr
}

func NewLPMTrie(m *ebpf.Map) *LPMTrie {
	return &LPMTrie{
		m: m,
	}
}

func (l *LPMTrie) Insert(prefix netip.Prefix) error {
	if !prefix.Addr().Is6() {
		return errors.New("prefix must be ipv6")
	}
	return l.m.Update(keyFromPrefix(prefix), byte(1), 0)
}

func (l *LPMTrie) Delete(prefix netip.Prefix) error {
	return l.m.Delete(keyFromPrefix(prefix))
}

func keyFromPrefix(p netip.Prefix) key {
	return key{
		PrefixLen: uint32(p.Bits()),
		Addr:      p.Addr().As16(),
	}
}
