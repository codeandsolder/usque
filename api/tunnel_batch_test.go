package api

import (
	"bytes"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

type fakeBatchTun struct {
	batchSize int

	readPackets [][]byte
	readOffset  int

	writePackets [][]byte
	writeOffset  int

	events chan tun.Event
}

func newFakeBatchTun(batchSize int) *fakeBatchTun {
	return &fakeBatchTun{
		batchSize: batchSize,
		events:    make(chan tun.Event),
	}
}

func (f *fakeBatchTun) File() *os.File {
	return nil
}

func (f *fakeBatchTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	f.readOffset = offset
	n := min(len(f.readPackets), len(bufs))
	for i := 0; i < n; i++ {
		copy(bufs[i][offset:], f.readPackets[i])
		sizes[i] = len(f.readPackets[i])
	}
	return n, nil
}

func (f *fakeBatchTun) Write(bufs [][]byte, offset int) (int, error) {
	f.writeOffset = offset
	f.writePackets = f.writePackets[:0]
	for _, buf := range bufs {
		pkt := append([]byte(nil), buf[offset:]...)
		f.writePackets = append(f.writePackets, pkt)
	}
	return len(bufs), nil
}

func (f *fakeBatchTun) MTU() (int, error) {
	return 1280, nil
}

func (f *fakeBatchTun) Name() (string, error) {
	return "fake0", nil
}

func (f *fakeBatchTun) Events() <-chan tun.Event {
	return f.events
}

func (f *fakeBatchTun) Close() error {
	return nil
}

func (f *fakeBatchTun) BatchSize() int {
	return f.batchSize
}

func TestNewBatchTunAdapterFallsBackForSinglePacketDevice(t *testing.T) {
	dev := newFakeBatchTun(1)
	adapter := NewBatchTunAdapter(dev)
	if _, ok := adapter.(*NetstackAdapter); !ok {
		t.Fatalf("NewBatchTunAdapter() = %T, want *NetstackAdapter for BatchSize 1", adapter)
	}
}

func TestBatchTunAdapterReadPacketBatchPreservesOffset(t *testing.T) {
	dev := newFakeBatchTun(4)
	dev.readPackets = [][]byte{{1, 2, 3}, {4, 5}}

	adapter, ok := NewBatchTunAdapter(dev).(BatchTunnelDevice)
	if !ok {
		t.Fatal("batch-capable device did not produce BatchTunnelDevice")
	}

	bufs := [][]byte{make([]byte, 8), make([]byte, 8), make([]byte, 8), make([]byte, 8)}
	sizes := make([]int, len(bufs))
	n, err := adapter.ReadPacketBatch(bufs, sizes, 1)
	if err != nil {
		t.Fatalf("ReadPacketBatch() error = %v", err)
	}
	if n != 2 {
		t.Fatalf("ReadPacketBatch() packets = %d, want 2", n)
	}
	if dev.readOffset != 1 {
		t.Fatalf("underlying Read() offset = %d, want 1", dev.readOffset)
	}
	if got := bufs[0][1 : 1+sizes[0]]; !bytes.Equal(got, dev.readPackets[0]) {
		t.Fatalf("first packet = %v, want %v", got, dev.readPackets[0])
	}
	if got := bufs[1][1 : 1+sizes[1]]; !bytes.Equal(got, dev.readPackets[1]) {
		t.Fatalf("second packet = %v, want %v", got, dev.readPackets[1])
	}
}

func TestBatchTunAdapterWritePacketBatchAddsVirtioHeadroom(t *testing.T) {
	dev := newFakeBatchTun(4)
	adapter, ok := NewBatchTunAdapter(dev).(BatchTunnelDevice)
	if !ok {
		t.Fatal("batch-capable device did not produce BatchTunnelDevice")
	}

	want := [][]byte{{1, 2, 3, 4}, {5, 6, 7}}
	if err := adapter.WritePacketBatch(want); err != nil {
		t.Fatalf("WritePacketBatch() error = %v", err)
	}
	if dev.writeOffset != virtioNetHeaderLen {
		t.Fatalf("underlying Write() offset = %d, want %d", dev.writeOffset, virtioNetHeaderLen)
	}
	if len(dev.writePackets) != len(want) {
		t.Fatalf("underlying Write() packet count = %d, want %d", len(dev.writePackets), len(want))
	}
	for i := range want {
		if !bytes.Equal(dev.writePackets[i], want[i]) {
			t.Fatalf("packet %d = %v, want %v", i, dev.writePackets[i], want[i])
		}
	}
}

func TestBatchTunAdapterWritePacketUsesBatchWritePath(t *testing.T) {
	dev := newFakeBatchTun(4)
	adapter := NewBatchTunAdapter(dev)

	want := []byte{9, 8, 7, 6}
	if err := adapter.WritePacket(want); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	if dev.writeOffset != virtioNetHeaderLen {
		t.Fatalf("underlying Write() offset = %d, want %d", dev.writeOffset, virtioNetHeaderLen)
	}
	if len(dev.writePackets) != 1 || !bytes.Equal(dev.writePackets[0], want) {
		t.Fatalf("underlying Write() packets = %v, want [%v]", dev.writePackets, want)
	}
}
