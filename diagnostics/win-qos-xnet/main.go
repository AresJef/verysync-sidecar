// This standalone fixture uses disposable local sockets and synthetic bytes.
// It tests the dependency's socket API and does not inspect packets.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type observation struct {
	Platform    string `json:"platform"`
	Family      string `json:"family"`
	Requested   int    `json:"requested"`
	SetError    string `json:"set_error"`
	GetError    string `json:"get_error"`
	ReadBack    int    `json:"read_back"`
	BytesEchoed int    `json:"bytes_echoed"`
}

func displayError(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func probe(network, host string, requested int) (observation, error) {
	row := observation{Platform: runtime.GOARCH, Family: network, Requested: requested}
	listener, err := net.ListenTCP(network, &net.TCPAddr{IP: net.ParseIP(host)})
	if err != nil {
		return row, err
	}
	defer listener.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := listener.SetDeadline(deadline); err != nil {
		return row, err
	}
	source, err := net.DialTimeout(network, listener.Addr().String(), 5*time.Second)
	if err != nil {
		return row, err
	}
	defer source.Close()
	receiver, err := listener.AcceptTCP()
	if err != nil {
		return row, err
	}
	defer receiver.Close()
	if err := source.SetDeadline(deadline); err != nil {
		return row, err
	}
	if err := receiver.SetDeadline(deadline); err != nil {
		return row, err
	}

	var setErr, getErr error
	if network == "tcp4" {
		socket := ipv4.NewConn(source)
		setErr = socket.SetTOS(requested)
		row.ReadBack, getErr = socket.TOS()
	} else {
		socket := ipv6.NewConn(source)
		setErr = socket.SetTrafficClass(requested)
		row.ReadBack, getErr = socket.TrafficClass()
	}
	row.SetError = displayError(setErr)
	row.GetError = displayError(getErr)
	payload := bytes.Repeat([]byte{3, 11, 79, byte(requested)}, 4096)
	if sent, err := source.Write(payload); err != nil || sent != len(payload) {
		return row, fmt.Errorf("write returned %d bytes, error %v", sent, err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(receiver, got); err != nil {
		return row, err
	}
	if !bytes.Equal(got, payload) {
		return row, fmt.Errorf("synthetic bytes changed")
	}
	if sent, err := receiver.Write(got); err != nil || sent != len(got) {
		return row, fmt.Errorf("echo returned %d bytes, error %v", sent, err)
	}
	for i := range got {
		got[i] = 0
	}
	if _, err := io.ReadFull(source, got); err != nil {
		return row, err
	}
	if !bytes.Equal(got, payload) {
		return row, fmt.Errorf("echo bytes changed")
	}
	row.BytesEchoed = len(got)
	return row, nil
}

func run() error {
	if runtime.GOOS != "windows" || len(os.Args) != 2 || runtime.GOARCH != os.Args[1] {
		return fmt.Errorf("expected native Windows for the selected architecture")
	}
	encoder := json.NewEncoder(os.Stdout)
	for _, family := range []struct{ network, host string }{
		{network: "tcp4", host: "127.0.0.1"},
		{network: "tcp6", host: "::1"},
	} {
		for _, requested := range []int{16, 32, 0} {
			row, err := probe(family.network, family.host, requested)
			if err != nil {
				return fmt.Errorf("%s value %d: %w", family.network, requested, err)
			}
			if err := encoder.Encode(row); err != nil {
				return err
			}
			if family.network == "tcp6" &&
				(!strings.Contains(row.SetError, "not implemented") ||
					!strings.Contains(row.GetError, "not implemented")) {
				return fmt.Errorf("IPv6 results differ from the pinned Windows dependency")
			}
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
