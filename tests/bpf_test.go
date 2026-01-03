//go:build linux

package nassauer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hown3d/nassauer/tests/logs"
	nassauermaps "github.com/hown3d/nassauer/tests/maps"
	"github.com/hown3d/nassauer/tests/types"
	"github.com/stretchr/testify/assert"
)

var objs nassauerObjects

func TestMain(m *testing.M) {
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("removing memlock", "err", err)
		os.Exit(1)
	}

	if err := loadNassauerObjects(&objs, nil); err != nil {
		slog.Error("loading nassauer into kernel", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	logBuf := new(bytes.Buffer)
	go func() {
		if err := startAyaLogger(ctx, logBuf, objs.AYA_LOGS); err != nil {
			slog.Error("running aya logger", "error", err)
		}
	}()
	code := m.Run()
	objs.Close()
	cancel()
	fmt.Printf("aya logs: \n%s", logBuf)
	os.Exit(code)
}

func TestEbpf(t *testing.T) {
	tests := []struct {
		name             string
		packet           []byte
		prefix           string
		expectedMessages []types.NeighborSolicitMessage
		expectedCode     uint32
	}{
		{
			name: "neighborSolicitPacket matches prefix populates map",
			packet: must(t, func() ([]byte, error) {
				return neighborSolicitPacket("00:11:22:33:44:55", "fe80::1", "fe80::2", "fe80::3")
			}),
			prefix: "fe80::/32",
			expectedMessages: []types.NeighborSolicitMessage{
				types.NewNeighborSolicitMessage("00:11:22:33:44:55", "fe80::1", "fe80::2", "fe80::3"),
			},
			expectedCode: 2,
		},

		{
			name: "neighborSolicitPacket without prefix match does not populate map",
			packet: must(t, func() ([]byte, error) {
				return neighborSolicitPacket("00:11:22:33:44:55", "fe80::1", "fe80::2", "fe80::3")
			}),
			prefix:           "abcd::/32",
			expectedMessages: []types.NeighborSolicitMessage{},
			expectedCode:     2,
		},
		{
			name: "packet without neighbor solicit header is not considered and just passed through",
			packet: must(t, func() ([]byte, error) {
				srcMacHW := mustParseMAC("00:11:22:33:44:55")
				dstMac := mustParseMAC("66:77:88:99:AA:BB")

				eth := &layers.Ethernet{
					// irrelevant, just to fill packet
					SrcMAC: srcMacHW,
					// irrelevant, just to fill packet
					DstMAC:       dstMac,
					EthernetType: layers.EthernetTypeIPv6,
				}
				ipv6 := &layers.IPv6{
					SrcIP:   netip.MustParseAddr("abcd::1").AsSlice(),
					DstIP:   netip.MustParseAddr("abcd::2").AsSlice(),
					Version: 6,
				}
				return serializePacketLayers(false, eth, ipv6)
			}),
			expectedMessages: []types.NeighborSolicitMessage{},
			expectedCode:     0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// setup ipv6 prefix lpm trie
			if tt.prefix != "" {
				prefix := netip.MustParsePrefix(tt.prefix)
				ipv6PrefixLPM := nassauermaps.NewLPMTrie(objs.IPV6PREFIXES)
				if err := ipv6PrefixLPM.Insert(prefix); err != nil {
					t.Fatalf("error inserting into prefix map: %s", err)
				}
				t.Cleanup(func() {
					ipv6PrefixLPM.Delete(prefix)
				})
			}

			nsMap, err := nassauermaps.NewNeighborSolicit(objs.SOLICIT)
			if err != nil {
				t.Fatalf("error creating neighborSolicit map: %s", err)
			}

			// run tests
			ret, _, err := objs.Nassauer.Test(tt.packet)
			if err != nil {
				t.Fatalf("testing ebpf program: %s", err)
			}
			assert.Equal(t, tt.expectedCode, ret, "ebpf return code")

			messages, err := nsMap.Messages()
			if err != nil {
				t.Fatalf("getting messages from solicit map: %s", err)
			}
			assert.ElementsMatch(t, messages, tt.expectedMessages, "neighbor solicit messages")
		})
	}
}

func startAyaLogger(ctx context.Context, out io.Writer, logMap *ebpf.Map) error {
	logger, err := logs.New(logMap, out)
	if err != nil {
		return fmt.Errorf("error loading logs from ebpf: %s", err)
	}
	defer logger.Close()
	if err := logger.Logs(ctx); err != nil {
		if ctx.Err() == nil {
			return err
		}
	}
	return nil
}

func neighborSolicitPacket(srcMac, src, dst, target string) ([]byte, error) {
	srcMacHW := mustParseMAC(srcMac)
	dstMac := mustParseMAC("66:77:88:99:AA:BB")

	eth := &layers.Ethernet{
		// irrelevant, just to fill packet
		SrcMAC: srcMacHW,
		// irrelevant, just to fill packet
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := &layers.IPv6{
		SrcIP:      netip.MustParseAddr(src).AsSlice(),
		DstIP:      netip.MustParseAddr(dst).AsSlice(),
		NextHeader: layers.IPProtocolICMPv6,
		Version:    6,
	}

	icmp6 := &layers.ICMPv6{
		// Need to provide both code as well as type
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
	}
	neighborSolicit := &layers.ICMPv6NeighborSolicitation{
		TargetAddress: netip.MustParseAddr(target).AsSlice(),
	}
	if err := icmp6.SetNetworkLayerForChecksum(ipv6); err != nil {
		return nil, err
	}
	return serializePacketLayers(true, eth, ipv6, icmp6, neighborSolicit)
}

func serializePacketLayers(computeChecksums bool, layers ...gopacket.SerializableLayer) ([]byte, error) {
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: computeChecksums,
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts, layers...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func must[T any](t *testing.T, f func() (T, error)) T {
	data, err := f()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustParseMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}
