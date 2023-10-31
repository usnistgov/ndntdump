// Package websocket parses WebSocket frames out of TCP payload.
package websocket

import (
	"encoding/binary"
	"errors"
)

var errTruncated = errors.New("truncated")

// WebSocket flags and opcodes.
const (
	FlagFin  = 0x80
	OpBinary = 0x02
)

// Frame contains a WebSocket frame.
type Frame struct {
	FlagOp     uint8
	MaskingKey []byte
	Payload    []byte
}

// Decode decodes a frame.
func (f *Frame) Decode(input []byte) (rest []byte, e error) {
	if len(input) < 2 {
		return nil, errTruncated
	}
	f.FlagOp = input[0]

	length, offset := int64(input[1]&0x7F), 2
	switch length {
	case 126:
		if len(input)-offset < 2 {
			return nil, errTruncated
		}
		length = int64(binary.BigEndian.Uint16(input[offset:]))
		offset += 2
	case 127:
		if len(input)-offset < 8 {
			return nil, errTruncated
		}
		length = int64(binary.BigEndian.Uint64(input[offset:]))
		offset += 8
	}

	if mask := input[1]&0x80 != 0; mask {
		if len(input)-offset < 4 {
			return nil, errTruncated
		}
		f.MaskingKey = input[offset : offset+4]
		offset += 4
	}

	end := offset + int(length)
	if length < 0 || len(input) < end {
		return nil, errTruncated
	}
	f.Payload = input[offset:end]
	return input[end:], nil
}

// Unmask changes MaskingKey to zero and reveals the payload.
func (f *Frame) Unmask() {
	if len(f.MaskingKey) == 0 || f.MaskingKey[0]|f.MaskingKey[1]|f.MaskingKey[2]|f.MaskingKey[3] == 0 {
		return
	}

	for i := range f.Payload {
		f.Payload[i] ^= f.MaskingKey[i%4]
	}
	clear(f.MaskingKey)
}

// ExtractBinaryFrames extracts unfragmented binary frames from TCP payload.
// Returns the first error encountered; extracted frames are still valid.
func ExtractBinaryFrames(input []byte) (frames []Frame, e error) {
	for len(input) > 0 {
		var f Frame
		input, e = f.Decode(input)
		if e != nil {
			return
		}

		if f.FlagOp != FlagFin|OpBinary {
			continue
		}

		f.Unmask()
		frames = append(frames, f)
	}
	return
}
