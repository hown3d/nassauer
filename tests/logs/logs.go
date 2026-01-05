package logs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func extractPrintableStrings(raw []byte) string {
	scan := bufio.NewScanner(bytes.NewBuffer(raw))
	scan.Split(bufio.ScanRunes)

	b := new(strings.Builder)

	wordBuilder := new(strings.Builder)
	for scan.Scan() {
		r, _ := utf8.DecodeRune(scan.Bytes())
		if r >= 0x20 && r <= 0x7E {
			wordBuilder.WriteRune(r)
		} else {
			fmt.Fprintf(b, "%s ", wordBuilder.String())
			wordBuilder.Reset()
		}
	}
	return b.String()
}

type logger struct {
	r   *ringbuf.Reader
	log *slog.Logger
}

func New(logMap *ebpf.Map, out io.Writer) (*logger, error) {
	reader, err := ringbuf.NewReader(logMap)
	if err != nil {
		return nil, err
	}

	return &logger{
		r:   reader,
		log: slog.New(slog.NewTextHandler(out, nil)).With("name", "aya-logs"),
	}, nil
}

func (l *logger) Close() error {
	return l.r.Close()
}

func (l *logger) Logs(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			record, err := l.r.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return err
				}
				return err
			}
			// fmt.Printf("retrieved record %x\n", record.RawSample)
			msg := extractPrintableStrings(record.RawSample)
			// progName := msg[1]
			l.log.Info(msg)
		}
	}
}
