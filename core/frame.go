package core

import (
	"encoding/binary"
	"fmt"
	"io"
)

// protocolVersion is stamped into every frame header, so peers can detect a
// version mismatch instead of silently misreading a newer wire format.
const protocolVersion = 1

// MsgType identifies what a frame's payload means. New kinds (file chunks,
// control messages) get new values here without changing the frame format.
type MsgType uint8

const (
	MsgChat MsgType = 1 // payload is a UTF-8 chat message
)

// headerSize is version(1) + type(1) + length(4).
const headerSize = 6

// maxPayload bounds a single frame. A length field is attacker-controlled, so
// without a cap a peer could send "length = 4 GiB" and make us allocate it; the
// cap turns that into a clean error instead of an out-of-memory kill.
const maxPayload = 1 << 20 // 1 MiB

// Frame is one length-prefixed message on the wire.
type Frame struct {
	Type    MsgType
	Payload []byte
}

// WriteFrame writes f to w as a single frame: the 6-byte header followed by the
// payload. It is the caller's job to serialize concurrent writes to w (a QUIC
// stream is a single ordered channel; interleaving two frames would corrupt it).
func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > maxPayload {
		return fmt.Errorf("frame payload too large: %d > %d", len(f.Payload), maxPayload)
	}
	var header [headerSize]byte
	header[0] = protocolVersion
	header[1] = byte(f.Type)
	binary.BigEndian.PutUint32(header[2:], uint32(len(f.Payload)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if _, err := w.Write(f.Payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	return nil
}

// ReadFrame reads exactly one frame from r. Because a QUIC stream is a byte
// stream (one Write does not equal one Read), we io.ReadFull the fixed header,
// learn the payload length, then io.ReadFull exactly that many payload bytes.
// A clean stream close surfaces as io.EOF from the header read, returned as-is
// so callers can distinguish "peer hung up" from a real protocol error.
func ReadFrame(r io.Reader) (Frame, error) {
	var header [headerSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	if header[0] != protocolVersion {
		return Frame{}, fmt.Errorf("unsupported protocol version %d", header[0])
	}
	length := binary.BigEndian.Uint32(header[2:])
	if length > maxPayload {
		return Frame{}, fmt.Errorf("frame payload too large: %d > %d", length, maxPayload)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, fmt.Errorf("read frame payload: %w", err)
	}
	return Frame{Type: MsgType(header[1]), Payload: payload}, nil
}
