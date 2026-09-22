package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/internal"
	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

// NetBuffer is a pool of byte slices with a fixed capacity.
// Helps to reduce memory allocations and improve performance.
// It uses a sync.Pool to manage the byte slices.
// The capacity of the byte slices is set when the pool is created.
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) Get() []byte {
	return *(n.buf.Get().(*[]byte))
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) Put(buf []byte) {
	if cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

// NewNetBuffer creates a new NetBuffer with the specified capacity.
// The capacity must be greater than 0.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("capacity must be greater than 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() interface{} {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
}

// BatchTunnelDevice extends TunnelDevice with packet-vector I/O. Linux native
// TUN uses this to preserve kernel GSO/GRO information and amortize syscalls.
// Other backends continue to use the single-packet methods above.
type BatchTunnelDevice interface {
	TunnelDevice
	BatchSize() int
	ReadPacketBatch(bufs [][]byte, sizes []int, offset int) (int, error)
	WritePacketBatch(pkts [][]byte) error
}

const (
	virtioNetHeaderLen = 10
	maxIPPacketSize    = 65535
)

// BatchTunAdapter wraps a tun.Device whose BatchSize is greater than one.
// The Linux wireguard-go TUN backend uses IFF_VNET_HDR, so writes need
// virtio-net header headroom. The adapter keeps that implementation detail
// out of MaintainTunnel and reuses large backing buffers for GRO.
type BatchTunAdapter struct {
	dev tun.Device

	writeMu      sync.Mutex
	writeBacking [][]byte
	writeViews   [][]byte
}

func (b *BatchTunAdapter) BatchSize() int {
	return b.dev.BatchSize()
}

func (b *BatchTunAdapter) ReadPacketBatch(bufs [][]byte, sizes []int, offset int) (int, error) {
	return b.dev.Read(bufs, sizes, offset)
}

func (b *BatchTunAdapter) ReadPacket(buf []byte) (int, error) {
	bufs := [][]byte{buf}
	sizes := []int{0}
	n, err := b.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, fmt.Errorf("batch TUN single-packet read returned %d packets", n)
	}
	return sizes[0], nil
}

func (b *BatchTunAdapter) ensureWriteBuffers(count int) {
	if len(b.writeBacking) != b.BatchSize() {
		b.writeBacking = make([][]byte, b.BatchSize())
		b.writeViews = make([][]byte, b.BatchSize())
	}
	for i := 0; i < count; i++ {
		if b.writeBacking[i] == nil {
			b.writeBacking[i] = make([]byte, virtioNetHeaderLen, virtioNetHeaderLen+maxIPPacketSize)
		}
	}
}

func (b *BatchTunAdapter) WritePacketBatch(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if len(pkts) > b.BatchSize() {
		return fmt.Errorf("batch TUN write has %d packets, maximum is %d", len(pkts), b.BatchSize())
	}

	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	b.ensureWriteBuffers(len(pkts))

	for i, pkt := range pkts {
		if len(pkt) > maxIPPacketSize {
			return fmt.Errorf("IP packet is too large: %d bytes", len(pkt))
		}
		view := b.writeBacking[i][:virtioNetHeaderLen+len(pkt)]
		copy(view[virtioNetHeaderLen:], pkt)
		b.writeViews[i] = view
	}

	_, err := b.dev.Write(b.writeViews[:len(pkts)], virtioNetHeaderLen)
	for i := range pkts {
		b.writeViews[i] = nil
	}
	return err
}

func (b *BatchTunAdapter) WritePacket(pkt []byte) error {
	return b.WritePacketBatch([][]byte{pkt})
}

// NewBatchTunAdapter creates a batching adapter when the device can batch.
// Devices with BatchSize 1 retain the existing single-packet adapter.
func NewBatchTunAdapter(dev tun.Device) TunnelDevice {
	if dev.BatchSize() < 2 {
		return NewNetstackAdapter(dev)
	}
	return &BatchTunAdapter{dev: dev}
}

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev             tun.Device
	tunnelBufPool   sync.Pool
	tunnelSizesPool sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
	}()

	(*packetBufsPtr)[0] = pkt
	_, err := n.dev.Write(*packetBufsPtr, 0)
	return err
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{
		dev: dev,
		tunnelBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([][]byte, 1)
				return &buf
			},
		},
		tunnelSizesPool: sync.Pool{
			New: func() interface{} {
				sizes := make([]int, 1)
				return &sizes
			},
		},
	}
}

// WaterAdapter wraps a *water.Interface so it satisfies TunnelDevice.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(buf []byte) (int, error) {
	n, err := w.iface.Read(buf)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) TunnelDevice {
	return &WaterAdapter{iface: iface}
}

// pumpShutdownGrace bounds how long the supervisor waits for both forwarding
// pumps to exit after an error before spawning a fresh pair. A device-side
// pump may still be parked in a blocking TUN read during this window; the
// readMu serializes any overlap with the next cycle's device reader.
const pumpShutdownGrace = 2 * time.Second

// CONNECT-IP context ID 0 is encoded as a one-byte QUIC varint. Reserving this
// byte before packets lets connect-ip-go send outbound datagrams in place.
const datagramContextIDHeadroom = 1

// MaintainTunnelConfig contains runtime settings for tunnel maintenance.
type MaintainTunnelConfig struct {
	TLSConfig         *tls.Config
	KeepalivePeriod   time.Duration
	InitialPacketSize uint16
	Endpoint          net.Addr
	Device            TunnelDevice
	MTU               int
	ReconnectDelay    time.Duration
	AlwaysReconnect   bool
	UseHTTP2          bool
	// LocalAddr optionally pins the source address for the MASQUERADE outbound
	// socket. When set, the kernel uses this IP as the source for the QUIC
	// (HTTP/3) or TCP (HTTP/2) connection to the CF endpoint. nil = let the
	// kernel pick (the default).
	LocalAddr *net.UDPAddr
	// OnConnect is a path to an executable run after every successful tunnel
	// connect. It is exec'd directly (no shell, no args) and runs fire-and-forget.
	OnConnect string
	// OnDisconnect is a path to an executable run after every tunnel loss.
	// It is exec'd directly (no shell, no args) and runs fire-and-forget.
	OnDisconnect string
	// HookEnv is a set of USQUE_* environment variables layered on top of the
	// parent process env for OnConnect / OnDisconnect invocations. USQUE_EVENT
	// and USQUE_ENDPOINT are set by MaintainTunnel itself.
	HookEnv map[string]string
}

// cloneHookEnv returns a shallow copy of src so concurrent hook invocations
// do not share a map.
func cloneHookEnv(src map[string]string) map[string]string {
	out := make(map[string]string, len(src)+2)
	for k, v := range src {
		out[k] = v
	}
	return out
}

// sleepCtx sleeps for d or until ctx is cancelled, whichever comes first.
// Returns ctx.Err() on cancellation and nil on normal completion.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - cfg: MaintainTunnelConfig - Tunnel maintenance runtime configuration.
func MaintainTunnel(ctx context.Context, cfg MaintainTunnelConfig) {
	if cfg.UseHTTP2 {
		if _, ok := cfg.Endpoint.(*net.TCPAddr); !ok {
			log.Fatalf("MaintainTunnel: HTTP/2 mode requires a *net.TCPAddr endpoint, got %T", cfg.Endpoint)
		}
	} else {
		if _, ok := cfg.Endpoint.(*net.UDPAddr); !ok {
			log.Fatalf("MaintainTunnel: HTTP/3 mode requires a *net.UDPAddr endpoint, got %T", cfg.Endpoint)
		}
	}

	packetBufferPool := NewNetBuffer(cfg.MTU + datagramContextIDHeadroom)
	batchDev, useBatch := cfg.Device.(BatchTunnelDevice)
	if useBatch && batchDev.BatchSize() < 2 {
		useBatch = false
	}

	type bufferedPacket struct {
		buf []byte
		n   int
	}
	releasePackets := func(packets []bufferedPacket) {
		for _, packet := range packets {
			packetBufferPool.Put(packet.buf)
		}
	}

	// A timed-out pump may remain blocked inside a device read after its
	// reconnect cycle is canceled. Keep this mutex for the lifetime of the
	// tunnel supervisor so a later cycle cannot start a second device reader.
	var readMu sync.Mutex

	for {
		if ctx.Err() != nil {
			return
		}

		var firstPackets []bufferedPacket
		if !cfg.AlwaysReconnect {
			log.Println("Tunnel idle. Waiting for outbound activity before reconnecting...")

			if useBatch {
				batchSize := batchDev.BatchSize()
				bufs := make([][]byte, batchSize)
				sizes := make([]int, batchSize)
				for i := range bufs {
					bufs[i] = packetBufferPool.Get()
				}

				readMu.Lock()
				nPackets, readErr := batchDev.ReadPacketBatch(bufs, sizes, datagramContextIDHeadroom)
				readMu.Unlock()
				if readErr != nil {
					for _, buf := range bufs {
						packetBufferPool.Put(buf)
					}
					log.Printf("Failed to read from TUN device while waiting for activity: %v", readErr)
					if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
						return
					}
					continue
				}

				firstPackets = make([]bufferedPacket, 0, nPackets)
				for i := 0; i < nPackets; i++ {
					firstPackets = append(firstPackets, bufferedPacket{buf: bufs[i], n: sizes[i]})
				}
				for i := nPackets; i < len(bufs); i++ {
					packetBufferPool.Put(bufs[i])
				}
				log.Printf("Detected outbound activity (%d packets). Reconnecting...", nPackets)
			} else {
				buf := packetBufferPool.Get()
				readMu.Lock()
				n, readErr := cfg.Device.ReadPacket(buf[datagramContextIDHeadroom:])
				readMu.Unlock()
				if readErr != nil {
					packetBufferPool.Put(buf)
					log.Printf("Failed to read from TUN device while waiting for activity: %v", readErr)
					if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
						return
					}
					continue
				}
				firstPackets = []bufferedPacket{{buf: buf, n: n}}
				log.Printf("Detected outbound activity (%d bytes). Reconnecting...", n)
			}
		}

		log.Printf("Establishing MASQUE connection to %s", cfg.Endpoint)
		udpConn, tr, ipConn, rsp, err := ConnectTunnel(
			ctx,
			cfg.TLSConfig,
			internal.DefaultQuicConfig(cfg.KeepalivePeriod, cfg.InitialPacketSize),
			internal.ConnectURI,
			cfg.Endpoint,
			cfg.UseHTTP2,
			cfg.LocalAddr,
		)
		if err != nil {
			releasePackets(firstPackets)
			log.Printf("Failed to connect tunnel: %v", err)
			if ipConn != nil {
				_ = ipConn.Close()
			}
			if tr != nil {
				_ = tr.Close()
			}
			if udpConn != nil {
				_ = udpConn.Close()
			}
			if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
				return
			}
			continue
		}
		if rsp.StatusCode != 200 {
			releasePackets(firstPackets)
			log.Printf("Tunnel connection failed: %s", rsp.Status)
			_ = ipConn.Close()
			if tr != nil {
				_ = tr.Close()
			}
			if udpConn != nil {
				_ = udpConn.Close()
			}
			if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
				return
			}
			continue
		}

		log.Println("Connected to MASQUE server")

		if cfg.OnConnect != "" {
			env := cloneHookEnv(cfg.HookEnv)
			env["USQUE_EVENT"] = "connect"
			env["USQUE_ENDPOINT"] = cfg.Endpoint.String()
			RunHook(cfg.OnConnect, env)
		}

		pumpCount := 3
		if useBatch {
			pumpCount++
		}
		errChan := make(chan error, pumpCount)
		pumpCtx, cancelPumps := context.WithCancel(ctx)
		var wg sync.WaitGroup
		icmpChan := make(chan []byte, 32)

		reportError := func(err error) {
			select {
			case errChan <- err:
			case <-pumpCtx.Done():
			}
		}

		wg.Add(pumpCount)

		go func() {
			defer wg.Done()
			for {
				select {
				case <-pumpCtx.Done():
					return
				case packet := <-icmpChan:
					if err := cfg.Device.WritePacket(packet); err != nil {
						reportError(fmt.Errorf("failed to write ICMP to TUN device: %w", err))
						return
					}
				}
			}
		}()

		go func(firstPackets []bufferedPacket) {
			defer wg.Done()

			sendPacket := func(buf []byte, n int) bool {
				icmp, writeErr := ipConn.WritePacketBuffer(buf, datagramContextIDHeadroom, n)
				if writeErr != nil {
					if errors.As(writeErr, new(*connectip.CloseError)) {
						reportError(fmt.Errorf("connection closed while writing to IP connection: %w", writeErr))
						return false
					}
					log.Printf("Error writing to IP connection: %v, continuing...", writeErr)
					return true
				}
				if len(icmp) > 0 {
					select {
					case icmpChan <- icmp:
					default:
						log.Println("Dropping ICMP packet: injector queue full")
					}
				}
				return true
			}

			for i, packet := range firstPackets {
				keepGoing := sendPacket(packet.buf, packet.n)
				packetBufferPool.Put(packet.buf)
				if !keepGoing {
					releasePackets(firstPackets[i+1:])
					return
				}
			}

			if useBatch {
				batchSize := batchDev.BatchSize()
				bufs := make([][]byte, batchSize)
				sizes := make([]int, batchSize)
				for i := range bufs {
					bufs[i] = packetBufferPool.Get()
				}
				defer func() {
					for _, buf := range bufs {
						packetBufferPool.Put(buf)
					}
				}()

				for {
					if pumpCtx.Err() != nil {
						return
					}
					readMu.Lock()
					nPackets, readErr := batchDev.ReadPacketBatch(bufs, sizes, datagramContextIDHeadroom)
					readMu.Unlock()
					if readErr != nil {
						reportError(fmt.Errorf("failed to read from TUN device: %w", readErr))
						return
					}
					if pumpCtx.Err() != nil {
						return
					}
					for i := 0; i < nPackets; i++ {
						if !sendPacket(bufs[i], sizes[i]) {
							return
						}
					}
				}
			}

			for {
				if pumpCtx.Err() != nil {
					return
				}
				buf := packetBufferPool.Get()
				readMu.Lock()
				n, readErr := cfg.Device.ReadPacket(buf[datagramContextIDHeadroom:])
				readMu.Unlock()
				if readErr != nil {
					packetBufferPool.Put(buf)
					reportError(fmt.Errorf("failed to read from TUN device: %w", readErr))
					return
				}
				if pumpCtx.Err() != nil {
					packetBufferPool.Put(buf)
					return
				}
				keepGoing := sendPacket(buf, n)
				packetBufferPool.Put(buf)
				if !keepGoing {
					return
				}
			}
		}(firstPackets)

		readFromTunnel := func() ([]byte, error) {
			for {
				packet, readErr := ipConn.ReadPacketZeroCopy(true)
				if readErr == nil {
					return packet, nil
				}
				if cfg.UseHTTP2 || errors.As(readErr, new(*connectip.CloseError)) {
					return nil, fmt.Errorf("connection closed while reading from IP connection: %w", readErr)
				}
				log.Printf("Error reading from IP connection: %v, continuing...", readErr)
			}
		}

		if useBatch {
			recvQueue := make(chan []byte, batchDev.BatchSize()*2)

			go func() {
				defer wg.Done()
				for {
					packet, readErr := readFromTunnel()
					if readErr != nil {
						reportError(readErr)
						return
					}
					select {
					case recvQueue <- packet:
					case <-pumpCtx.Done():
						return
					}
				}
			}()

			go func() {
				defer wg.Done()
				batch := make([][]byte, batchDev.BatchSize())

				for {
					var packet []byte
					select {
					case packet = <-recvQueue:
					case <-pumpCtx.Done():
						return
					}

					batch[0] = packet
					n := 1
				drain:
					for n < len(batch) {
						select {
						case packet = <-recvQueue:
							batch[n] = packet
							n++
						default:
							break drain
						}
					}

					writeErr := batchDev.WritePacketBatch(batch[:n])
					clear(batch[:n])
					if writeErr != nil {
						reportError(fmt.Errorf("failed to write batch to TUN device: %w", writeErr))
						return
					}
				}
			}()
		} else {
			go func() {
				defer wg.Done()
				for {
					packet, readErr := readFromTunnel()
					if readErr != nil {
						reportError(readErr)
						return
					}
					if writeErr := cfg.Device.WritePacket(packet); writeErr != nil {
						reportError(fmt.Errorf("failed to write to TUN device: %w", writeErr))
						return
					}
				}
			}()
		}

		err = <-errChan
		log.Printf("Tunnel connection lost: %v. Reconnecting...", err)

		if cfg.OnDisconnect != "" {
			env := cloneHookEnv(cfg.HookEnv)
			env["USQUE_EVENT"] = "disconnect"
			env["USQUE_ENDPOINT"] = cfg.Endpoint.String()
			RunHook(cfg.OnDisconnect, env)
		}

		cancelPumps()
		_ = ipConn.Close()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(pumpShutdownGrace):
			log.Printf("Pump shutdown grace of %s expired; a stale TUN reader may still be parked (readMu will serialize next cycle)", pumpShutdownGrace)
		}

		if tr != nil {
			_ = tr.Close()
		}
		if udpConn != nil {
			_ = udpConn.Close()
		}
		if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
			return
		}
	}
}
