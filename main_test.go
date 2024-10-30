package main

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

// 32bit random mask
var mask = []byte{
	0b11000011,
	0b00001010,
	0b10110100,
	0b11001100,
}

func newMaskedCloseFrame(code StatusCode, message string) []byte {
	frame := make([]byte, 0)

	frame = append(
		frame,
		0b10001000, // fin, opcode: close
		0b10001010, // mask, payload len: 10
	)
	frame = append(frame, mask...)
	frame = append(frame, code.Bytes()...)
	frame = append(frame, message...)

	return frame
}

func TestControlFrameNotFinalError(t *testing.T) {
	f := Frame{
		final:      false,
		opcode:     ConnectionClose,
		mask:       true,
		payloadLen: 12,
		maskingKey: mask,
		appData:    []byte("some message"),
	}

	_, err := NewFrame(f.Bytes(), true)
	assert.NotNil(t, err)
	assert.Equal(t, "control frames cannot be fragmented", err.Error())
}

func TestControlFrameLargePayloadError(t *testing.T) {
	message := strings.Repeat("0123456789", 13)
	f := Frame{
		final:      true,
		opcode:     ConnectionClose,
		mask:       true,
		payloadLen: uint(len(message)),
		maskingKey: mask,
		appData:    []byte(message),
	}

	_, err := NewFrame(f.Bytes(), true)
	assert.NotNil(t, err)
	assert.Equal(t, "control frames must not have payload length > 125", err.Error())
}

// todo we shouldn't really be relying on Frame.Bytes() as that's mostly what we wanna test either way
// maybe the best idea is to grab some valid websocket messages in bytes from the interwebs and use that
// in the tests instead

func TestNewCloseFrame(t *testing.T) {
	isServer := false
	frameData := newMaskedCloseFrame(Done, "message!")
	f, err := NewFrame(frameData, isServer)
	if err != nil {
		assert.Nilf(t, err, "Failed to create frame, err: %s", err.Error())
	}
	assert.Equal(t, true, f.final)
	assert.Equal(t, ConnectionClose, f.opcode)
	assert.Equal(t, true, f.mask)
	assert.Equal(t, uint(10), f.payloadLen)
	assert.Equal(t, mask, f.maskingKey)
	assert.Equal(t, Done.Bytes(), f.appData[:2])
	assert.Equal(t, "message!", string(f.appData[2:]))
}

func TestMaskedCloseFrameBytes(t *testing.T) {
	f := Frame{
		final:      true,
		opcode:     ConnectionClose,
		mask:       true,
		payloadLen: 10,
		maskingKey: mask,
		appData:    append(Done.Bytes(), "message!"...),
	}

	actual := f.Bytes()

	assert.Equal(t, 1+1+4+10, len(actual))
	assert.Equal(t, byte(0b10000000), actual[0]&0b10000000)  // final
	assert.Equal(t, f.opcode, Opcode(actual[0]&0b00001111))  // opcode
	assert.Equal(t, uint8(0b10000000), actual[1]&0b10000000) // mask
	assert.Equal(t, byte(f.payloadLen), actual[1]&0b01111111)
	assert.Equal(t, f.maskingKey, actual[2:6])
	unmaskedAppData := make([]byte, len(f.appData))
	copy(unmaskedAppData, actual[6:])
	applyMask(unmaskedAppData, mask)

	assert.Equal(t, Done.Bytes(), unmaskedAppData[:2])
	assert.Equal(t, "message!", string(unmaskedAppData[2:]))
}

func TestCloseFrameBytes(t *testing.T) {
	f := Frame{
		final:      true,
		opcode:     ConnectionClose,
		mask:       false,
		payloadLen: 10,
		maskingKey: []byte{},
		appData:    append(Done.Bytes(), "message!"...),
	}

	actual := f.Bytes()

	assert.Equal(t, 1+1+10, len(actual))
	assert.Equal(t, byte(0b10000000), actual[0]&0b10000000)  // final
	assert.Equal(t, f.opcode, Opcode(actual[0]&0b00001111))  // opcode
	assert.Equal(t, uint8(0b00000000), actual[1]&0b10000000) // mask
	assert.Equal(t, byte(f.payloadLen), actual[1]&0b01111111)

	assert.Equal(t, Done.Bytes(), f.appData[:2])
	assert.Equal(t, "message!", string(f.appData[2:]))
}

func TestUnmaskedServerFrameErrors(t *testing.T) {
	f := Frame{
		final:      true,
		opcode:     ConnectionClose,
		mask:       false,
		payloadLen: 12,
		maskingKey: mask,
		appData:    []byte("some message"),
	}
	_, err := NewFrame(f.Bytes(), true)
	assert.NotNil(t, err)
	assert.Equal(t, "Got a frame that is not masked", err.Error())
}
