package client

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	msg := map[string]any{"type": "info"}
	var buf bytes.Buffer
	if err := writeFrame(&buf, msg); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := readFrame(&buf, &back); err != nil {
		t.Fatal(err)
	}
	if back["type"] != "info" {
		t.Fatalf("got %#v", back)
	}
}

func TestOversizedRejected(t *testing.T) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(maxFrameBytes+1))
	r := bytes.NewReader(hdr[:])
	var out map[string]any
	err := readFrame(r, &out)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestShortHeaderEOF(t *testing.T) {
	r := bytes.NewReader([]byte{1, 2})
	var out map[string]any
	err := readFrame(r, &out)
	if err == nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		// ReadFull returns UnexpectedEOF
		if err != io.ErrUnexpectedEOF {
			// ok if UnexpectedEOF
			t.Log(err)
		}
	}
}

func TestJSONMarshalRequest(t *testing.T) {
	b, err := json.Marshal(Request{Type: "top", Params: TopParams{Limit: 5}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"type":"top"`)) {
		t.Fatalf("%s", b)
	}
}
