package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"
)

type Event int

const (
	EventUp = 1 << iota
	EventDown
	EventMTUUpdate
)

type Device interface {
	File() *os.File
	Read(bufs [][]byte, sizes []int, offset int) (n int, err error)
	Write(bufs [][]byte, offset int) (int, error)
	MTU() (int, error)
	Name() (string, error)
	Events() <-chan Event
	Close() error
	BatchSize() int
}

const (
	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)
	spinloopRateThreshold      = 800000000 / 8
	spinloopDuration           = uint64(time.Millisecond / 80 / time.Nanosecond)
)

type rateJuggler struct {
	current       atomic.Uint64
	nextByteCount atomic.Uint64
	nextStartTime atomic.Int64
	changing      atomic.Bool
}

type NativeTun struct {
	wt        *wintun.Adapter
	name      string
	handle    windows.Handle
	rate      rateJuggler
	session   wintun.Session
	readWait  windows.Handle
	events    chan Event
	running   sync.WaitGroup
	closeOnce sync.Once
	close     atomic.Bool
	forcedMTU int
	outSizes  []int
}

var (
	WintunTunnelType          = "WireGuard"
	WintunStaticRequestedGUID *windows.GUID
)

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

func CreateTUN(ifname string, mtu int) (Device, error) {
	return CreateTUNWithRequestedGUID(ifname, WintunStaticRequestedGUID, mtu)
}

func CreateTUNWithRequestedGUID(ifname string, requestedGUID *windows.GUID, mtu int) (Device, error) {
	wt, err := wintun.CreateAdapter(ifname, WintunTunnelType, requestedGUID)
	if err != nil {
		return nil, fmt.Errorf("Error creating interface: %w", err)
	}

	forcedMTU := 1420
	if mtu > 0 {
		forcedMTU = mtu
	}

	tun := &NativeTun{
		wt:        wt,
		name:      ifname,
		handle:    windows.InvalidHandle,
		events:    make(chan Event, 10),
		forcedMTU: forcedMTU,
	}

	tun.session, err = wt.StartSession(0x800000)
	if err != nil {
		tun.wt.Close()
		close(tun.events)
		return nil, fmt.Errorf("Error starting session: %w", err)
	}
	tun.readWait = tun.session.ReadWaitEvent()
	return tun, nil
}

func (tun *NativeTun) Name() (string, error) {
	return tun.name, nil
}

func (tun *NativeTun) File() *os.File {
	return nil
}

func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

func (tun *NativeTun) Close() error {
	var err error
	tun.closeOnce.Do(func() {
		tun.close.Store(true)
		windows.SetEvent(tun.readWait)
		tun.running.Wait()
		tun.session.End()
		if tun.wt != nil {
			tun.wt.Close()
		}
		close(tun.events)
	})
	return err
}

func (tun *NativeTun) MTU() (int, error) {
	return tun.forcedMTU, nil
}

func (tun *NativeTun) ForceMTU(mtu int) {
	if tun.close.Load() {
		return
	}
	update := tun.forcedMTU != mtu
	tun.forcedMTU = mtu
	if update {
		tun.events <- EventMTUUpdate
	}
}

func (tun *NativeTun) BatchSize() int {
	return 1
}

func (tun *NativeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	tun.running.Add(1)
	defer tun.running.Done()
retry:
	if tun.close.Load() {
		return 0, os.ErrClosed
	}
	start := nanotime()
	shouldSpin := tun.rate.current.Load() >= spinloopRateThreshold && uint64(start-tun.rate.nextStartTime.Load()) <= rateMeasurementGranularity*2
	for {
		if tun.close.Load() {
			return 0, os.ErrClosed
		}
		packet, err := tun.session.ReceivePacket()
		switch err {
		case nil:
			n := copy(bufs[0][offset:], packet)
			sizes[0] = n
			tun.session.ReleaseReceivePacket(packet)
			tun.rate.update(uint64(n))
			return 1, nil
		case windows.ERROR_NO_MORE_ITEMS:
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				windows.WaitForSingleObject(tun.readWait, windows.INFINITE)
				goto retry
			}
			procyield(1)
			continue
		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			return 0, errors.New("Send ring corrupt")
		}
		return 0, fmt.Errorf("Read failed: %w", err)
	}
}

func (tun *NativeTun) Write(bufs [][]byte, offset int) (int, error) {
	tun.running.Add(1)
	defer tun.running.Done()
	if tun.close.Load() {
		return 0, os.ErrClosed
	}

	for i, buf := range bufs {
		packetSize := len(buf) - offset
		tun.rate.update(uint64(packetSize))

		packet, err := tun.session.AllocateSendPacket(packetSize)
		switch err {
		case nil:
			// TODO: Explore options to eliminate this copy.
			copy(packet, buf[offset:])
			tun.session.SendPacket(packet)
			continue
		case windows.ERROR_HANDLE_EOF:
			return i, os.ErrClosed
		case windows.ERROR_BUFFER_OVERFLOW:
			continue
		default:
			return i, fmt.Errorf("Write failed: %w", err)
		}
	}
	return len(bufs), nil
}

func (tun *NativeTun) LUID() uint64 {
	tun.running.Add(1)
	defer tun.running.Done()
	if tun.close.Load() {
		return 0
	}
	return tun.wt.LUID()
}

func (tun *NativeTun) RunningVersion() (version uint32, err error) {
	return wintun.RunningVersion()
}

func (rate *rateJuggler) update(packetLen uint64) {
	now := nanotime()
	total := rate.nextByteCount.Add(packetLen)
	period := uint64(now - rate.nextStartTime.Load())
	if period >= rateMeasurementGranularity {
		if !rate.changing.CompareAndSwap(false, true) {
			return
		}
		rate.nextStartTime.Store(now)
		rate.current.Store(total * uint64(time.Second/time.Nanosecond) / period)
		rate.nextByteCount.Store(0)
		rate.changing.Store(false)
	}
}

func parsePacket(data []byte) {
	hdr, err := ipv4.ParseHeader(data)
	if err != nil {
		log.Println("Failed to parse IP header:", err)
		return
	}

	switch hdr.Protocol {
	case 6:
		log.Println("TCP packet")
		log.Printf("Packet data:\n%s", hex.Dump(data))
		parseTCP(data)
	case 17:
		log.Println("UDP packet")
		log.Printf("Packet data:\n%s", hex.Dump(data))
		parseUDP(data)
	default:
		log.Printf("Other protocol: %d", hdr.Protocol)
	}
}

func parseTCP(data []byte) {
	tcpHdr, err := ParseTCPHeader(data)
	fmt.Println("tcpHdr", tcpHdr)
	if err != nil {
		log.Println("Failed to parse TCP header:", err)
		return
	}
	log.Printf("TCP header: %+v", tcpHdr)
	log.Printf("TCP: %d -> %d, Seq: %d, Ack: %d, Flags: %08b, Window: %d",
		tcpHdr.SrcPort, tcpHdr.DstPort, tcpHdr.SeqNum, tcpHdr.AckNum, tcpHdr.Flags, tcpHdr.Window)
}

func parseUDP(data []byte) {
	udpHdr, err := ParseUDPHeader(data)
	fmt.Println("udpHdr", udpHdr)
	if err != nil {
		log.Println("Failed to parse UDP header:", err)
		return
	}
	log.Printf("UDP header: %+v", udpHdr)
	log.Printf("UDP: %d -> %d, Length: %d",
		udpHdr.SrcPort, udpHdr.DstPort, udpHdr.Length)
}

func ParseTCPHeader(data []byte) (*TCPHeader, error) {
	if len(data) < 20 {
		return nil, errors.New("TCP header too short")
	}

	h := &TCPHeader{}
	h.SrcPort = binary.BigEndian.Uint16(data[0:2])
	h.DstPort = binary.BigEndian.Uint16(data[2:4])
	h.SeqNum = binary.BigEndian.Uint32(data[4:8])
	h.AckNum = binary.BigEndian.Uint32(data[8:12])
	h.DataOff = data[12] >> 4
	h.Flags = data[13] & 0x3F
	h.Window = binary.BigEndian.Uint16(data[14:16])
	h.Checksum = binary.BigEndian.Uint16(data[16:18])
	h.Urgent = binary.BigEndian.Uint16(data[18:20])

	headerLen := int(h.DataOff) * 4
	if headerLen > 20 {
		if len(data) < headerLen {
			return nil, errors.New("TCP options truncated")
		}
		h.Options = make([]byte, headerLen-20)
		copy(h.Options, data[20:headerLen])
	}

	return h, nil
}

type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

type TCPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	SeqNum   uint32
	AckNum   uint32
	DataOff  uint8
	Flags    uint8
	Window   uint16
	Checksum uint16
	Urgent   uint16
	Options  []byte
}

func ParseUDPHeader(data []byte) (*UDPHeader, error) {
	if len(data) < 8 {
		return nil, errors.New("UDP header too short")
	}

	h := &UDPHeader{}
	h.SrcPort = binary.BigEndian.Uint16(data[0:2])
	h.DstPort = binary.BigEndian.Uint16(data[2:4])
	h.Length = binary.BigEndian.Uint16(data[4:6])
	h.Checksum = binary.BigEndian.Uint16(data[6:8])

	return h, nil
}

func main() {
	tun, err := CreateTUN("tun0", 1500)
	if err != nil {
		log.Fatalf("Failed to create TUN interface: %v", err)
	}
	defer tun.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		sizes := make([]int, 1)
		for {
			n, err := tun.Read([][]byte{buf}, sizes, 0)
			if err != nil {
				log.Printf("Failed to read from TUN interface: %v", err)
				return
			}
			if n > 0 {
				parsePacket(buf[:sizes[0]])
			}
		}
	}()
	wg.Wait()
}
