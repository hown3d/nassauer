package maps

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/hown3d/nassauer/tests/types"
)

type NeighborSolicit struct {
	r *ringbuf.Reader
}

func NewNeighborSolicit(m *ebpf.Map) (*NeighborSolicit, error) {
	r, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, err
	}
	return &NeighborSolicit{
		r: r,
	}, nil
}

func (s *NeighborSolicit) Messages() ([]types.NeighborSolicitMessage, error) {
	err := s.r.Flush()
	if err != nil {
		return nil, err
	}
	messages := []types.NeighborSolicitMessage{}
	for {
		record, err := s.r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) {
				break
			}
			return nil, err
		}
		var ns types.NeighborSolicitMessage
		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := ns.UnmarshalBinary(record.RawSample); err != nil {
			return nil, fmt.Errorf("unmarshaling neighbor solicit message: %w", err)
		}
		messages = append(messages, ns)
	}
	return messages, nil
}
