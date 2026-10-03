package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestExchangeVerifiesLargePayload(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	payload := bytes.Repeat([]byte("forwarded payload"), 65536)
	if err := exchange(client, payload, time.Second); err != nil {
		t.Fatalf("verified exchange: %v", err)
	}
}

func TestExchangeRejectsCorruptOrPartialReplies(t *testing.T) {
	for _, reply := range [][]byte{[]byte("wrong"), []byte("tes")} {
		t.Run(string(reply), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			go func() {
				defer server.Close()
				_, _ = io.CopyN(io.Discard, server, 5)
				_, _ = server.Write(reply)
			}()
			if err := exchange(client, []byte("tests"), time.Second); err == nil {
				t.Fatal("unverified reply was accepted")
			}
		})
	}
}

func TestExchangeDeadlineCoversMissingReply(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if err := exchange(client, []byte("tests"), 20*time.Millisecond); err == nil {
		t.Fatal("missing reply was accepted")
	}
}
