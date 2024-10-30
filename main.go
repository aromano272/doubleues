package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type Opcode byte

const (
	ContinuationFrame Opcode = 0
	TextFrame         Opcode = 1
	BinaryFrame       Opcode = 2
	ConnectionClose   Opcode = 8
	Ping              Opcode = 9
	Pong              Opcode = 10
)

type StatusCode uint16

const (
	Done                          StatusCode = 1000
	Exit                          StatusCode = 1001
	ProtocolError                 StatusCode = 1002
	UnsupportedPayload            StatusCode = 1003
	NoStatusCode                  StatusCode = 1005
	ClosedAbnormally              StatusCode = 1006
	PayloadDidNotMatchMessageType StatusCode = 1007
	PolicyViolation               StatusCode = 1008
	MessageTooBig                 StatusCode = 1009
	ExtensionNotFound             StatusCode = 1010
	Unexpected                    StatusCode = 1011
	FailedTLSHandshake            StatusCode = 1015
)

func (sc StatusCode) Bytes() []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, uint16(sc))
	return data
}

type ConnState struct {
	//conn      net.Conn
	r         io.Reader
	w         io.Writer
	isClosing bool
}

type Frame struct {
	final         bool
	opcode        Opcode
	mask          bool
	payloadLen    uint
	maskingKey    []byte
	appData       []byte
	maskedAppData []byte
}

func (f *Frame) Bytes() []byte {
	buf := make([]byte, 0)

	//                FIN
	var fin byte = 0b00000000
	var opcode = byte(f.opcode)
	if f.final {
		fin = 0b10000000
	}
	buf = append(buf, fin|opcode)
	var mask byte = 0b00000000
	if f.mask {
		mask = 0b10000000
	}
	maxUint16 := ^uint16(0)
	if f.payloadLen > uint(maxUint16) {
		buf = append(buf, mask|127)
		buf = binary.BigEndian.AppendUint64(buf, uint64(f.payloadLen))
	} else if f.payloadLen > 125 {
		buf = append(buf, mask|126)
		buf = binary.BigEndian.AppendUint16(buf, uint16(f.payloadLen))
	} else {
		buf = append(buf, mask|byte(f.payloadLen))
	}

	if f.mask {
		buf = append(buf, f.maskingKey...)

		appData := make([]byte, len(f.appData))
		copy(appData, f.appData)
		applyMask(appData, f.maskingKey)

		buf = append(buf, appData...)
	} else {
		buf = append(buf, f.appData...)
	}

	// todo extension data

	return buf
}

func NewFrame(bytes []byte, isServer bool) (*Frame, error) {
	if len(bytes) < 2 {
		err := errors.New("message size < 2 bytes")
		return nil, err
	}

	var bufCursor uint = 0
	final := bytes[bufCursor] & 0b10000000
	isFinal := final != 0
	rsv1 := bytes[bufCursor] & 0b01000000
	rsv2 := bytes[bufCursor] & 0b00100000
	rsv3 := bytes[bufCursor] & 0b00010000

	if rsv1 > 0 || rsv2 > 0 || rsv3 > 0 {
		err := errors.New(fmt.Sprintf("rsv not 0, rsv1: %t, rsv2: %t, rsv3: %t\n", rsv1 > 0, rsv2 > 0, rsv3 > 0))
		return nil, err
	}

	opcode := Opcode(bytes[bufCursor] & 0b00001111)
	isControl := ConnectionClose >= opcode && opcode <= Pong
	bufCursor++

	if (2 < opcode && opcode < 8) || opcode > 10 {
		err := errors.New(fmt.Sprintf("opcode b: %b, d: %d not recognized\n", opcode, opcode))
		return nil, err
	}

	mask := bytes[bufCursor] & 0b10000000
	hasMask := mask != 0
	if !hasMask && isServer {
		// todo close connection with 1002, ProtocolError
		err := errors.New(fmt.Sprintf("Got a frame that is not masked"))
		return nil, err
	}
	encodedPayloadLen := bytes[bufCursor] & 0b01111111
	bufCursor++

	var payloadLen uint
	if encodedPayloadLen < 126 {
		payloadLen = uint(encodedPayloadLen)
	} else if encodedPayloadLen == 126 {
		payloadLen = uint(binary.BigEndian.Uint16(bytes[bufCursor : bufCursor+2]))
		bufCursor += 2
	} else {
		payloadLen = uint(binary.BigEndian.Uint64(bytes[bufCursor : bufCursor+8]))
		bufCursor += 8
	}

	var maskingKey []byte
	if hasMask {
		maskingKey = bytes[bufCursor : bufCursor+4]
		bufCursor += 4
	}

	// todo	extension data

	appData := bytes[bufCursor : bufCursor+payloadLen]

	var maskedAppData []byte
	if hasMask {
		maskedAppData = append(maskedAppData, appData...)
		applyMask(appData, maskingKey)
	}

	if isControl {
		if !isFinal {
			err := errors.New("control frames cannot be fragmented")
			return nil, err
		}
		if payloadLen > 125 {
			err := errors.New("control frames must not have payload length > 125")
			return nil, err
		}
	}

	frame := &Frame{
		final:         isFinal,
		opcode:        opcode,
		mask:          hasMask,
		payloadLen:    payloadLen,
		maskingKey:    maskingKey,
		appData:       appData,
		maskedAppData: maskedAppData,
	}

	return frame, nil
}

func main() {
	http.HandleFunc("/funky", funky)
	log.Fatal(http.ListenAndServe(":80", nil))
}

func funky(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "" {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Printf("Method not GET, method: %s\n", r.Method)
		return
	}

	if r.ProtoMajor < 1 && r.ProtoMinor < 1 {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Printf("Proto not > HTTP/1.1, proto: %s\n", r.Proto)
		return
	}

	if _, err := checkHeader(r, "Upgrade", "websocket"); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Println(err.Error())
		return
	}

	if _, err := checkHeader(r, "Connection", "Upgrade"); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Println(err.Error())
		return
	}

	secWebSocketKey, err := checkHeaderExists(r, "Sec-WebSocket-Key")
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Println(err.Error())
		return
	}
	// todo more thorough validation
	secWebSocketKeyDecoded, err := base64.StdEncoding.DecodeString(secWebSocketKey)
	if err != nil || len(secWebSocketKeyDecoded) != 16 {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Printf("Invalid value for Sec-WebSocket-Key header %s\n", secWebSocketKey)
		return
	}

	// todo validate origin

	_, err = checkHeader(r, "Sec-WebSocket-Version", "13")
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Println(err.Error())
		return
	}

	// todo subprotocols Sec-WebSocket-Protocol

	// todo extensions Sec-WebSocket-Extensions

	netConn, _, err := http.NewResponseController(rw).Hijack()
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		fmt.Printf("Couldn't hijack the connection, err: %s", err.Error())
		return
	}

	defer netConn.Close()

	// todo	write http.SwitchingProtocols 101
	// todo write Upgrade -> websocket header
	// todo write Connection -> Upgrade header

	// todo write Sec-WebSocket-Accept -> base64(sha1(secWebSocketKeyDecoded+acceptSeed))
	acceptSeed := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	acceptData := secWebSocketKey + acceptSeed
	acceptSha1 := sha1.Sum([]byte(acceptData))
	acceptVal := base64.StdEncoding.EncodeToString(acceptSha1[:])

	// todo extensions Sec-WebSocket-Extensions

	// todo subprotocols Sec-WebSocket-Protocol

	writeBuf := bytes.Buffer{}
	writeBuf.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	respHeaders := http.Header{}
	respHeaders.Add("Upgrade", "websocket")
	respHeaders.Add("Connection", "Upgrade")
	respHeaders.Add("Sec-WebSocket-Accept", acceptVal)
	respHeaders.Write(&writeBuf)
	writeBuf.WriteString("\r\n") // End headers with an extra CRLF to signify end of headers

	println(writeBuf.String())
	if err = netConn.SetWriteDeadline(time.Time{}); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		fmt.Printf("Couldn't set write deadline, err: %s", err.Error())
		return
	}

	if _, err := netConn.Write(writeBuf.Bytes()); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		fmt.Printf("Couldn't set write deadline, err: %s", err.Error())
		return
	}

	connState := ConnState{
		r: netConn,
		w: netConn,
	}

	handleFrames(connState)

	fmt.Printf("Connection: %s\n", netConn.RemoteAddr().String())

}

func createCloseFrame(
	code StatusCode,
	reason string,
) Frame {
	var f = Frame{
		final:      true,
		opcode:     ConnectionClose,
		mask:       false,
		payloadLen: uint(2 + len(reason)),
		maskingKey: []byte{},
		appData:    append(code.Bytes(), reason...),
	}
	return f
}

var isServer = true

func handleFrames(connState ConnState) {
	r := connState.r
	//w := connState.w
	for {
		buf := make([]byte, 1024)
		n, err := r.Read(buf)
		if err != nil {
			if err == io.EOF {
				fmt.Println("Connection closed by client")
			} else {
				fmt.Printf("Error reading from connection: %v\n", err)
			}
			return
		}
		fmt.Printf("Received: %s\n", string(buf[:n]))

		f, err := NewFrame(buf, !isServer)
		if err != nil {
			fmt.Printf("Failed to decode frame, error: %s\n", err.Error())
			return
		}

		if f.opcode == ConnectionClose {
			// todo rfc section 7.4
			var code StatusCode = NoStatusCode // default code when no code is provided in the message
			var reason []byte
			if f.payloadLen >= 2 {
				code = StatusCode(binary.BigEndian.Uint16(f.appData[:2]))
				reason = f.appData[2:]
			}
			fmt.Printf("ConnectionClose frame, code: %d, reason: %s\n", code, reason)

			/*
				if we haven't sent a connclose yet, we send it now, we may delay this connclose if we're in
				the middle of sending a fragmented message, we may choose to send the remaining fragments
				and only then close the connection
			*/
			if connState.isClosing {
				fmt.Printf("Closing connection\n")
				return
			} else {
				// todo send connclose with `code`
				// todo replace with
				frame := createCloseFrame(code, "")
				fmt.Printf("Sending ConnectionClose frame\n")

				if err := connState.SendFrame(frame); err != nil {
					fmt.Printf("Sending ConnectionClose frame failed, err: %s\n", err.Error())
					return
				}
				connState.isClosing = true
			}
		}
	}
}

func (cs *ConnState) SendFrame(f Frame) error {
	data := f.Bytes()
	fmt.Printf("SendFrame data: %08b\n", data)
	if _, err := cs.w.Write(data); err != nil {
		return err
	}
	return nil
}

func applyMask(data []byte, mask []byte) {
	for i, _ := range data {
		data[i] ^= mask[i%4]
	}
}

func checkHeader(r *http.Request, header string, expected string) (string, error) {
	actual := r.Header.Get(header)
	if actual != expected {
		err := fmt.Sprintf("%s header not %s, header: %s\n", header, expected, actual)
		return "", errors.New(err)
	}
	return actual, nil
}

func checkHeaderExists(r *http.Request, header string) (string, error) {
	actual := r.Header.Get(header)
	if actual == "" {
		err := fmt.Sprintf("%s header not found, header: %s\n", header, actual)
		return "", errors.New(err)
	}
	return actual, nil
}
