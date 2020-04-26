// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp_zero_window_probe_test

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

// TestZeroWindowProbe tests few cases of zero window probing over the
// same connection.
func TestZeroWindowProbe(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFd)
	conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()

	conn.Handshake()
	acceptFd, _ := dut.Accept(listenFd)
	defer dut.Close(acceptFd)

	dut.SetSockOptInt(acceptFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

	sampleData := []byte("Sample Data")
	samplePayload := &tb.Payload{Bytes: sampleData}

	// Send and receive sample data to the dut.
	dut.Send(acceptFd, sampleData, 0)
	if _, err := conn.ExpectData(&tb.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
	}
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}, samplePayload)
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)}, nil, time.Second); err != nil {
		t.Fatalf("expected a packet with sequence number %s", err)
	}

	// Test 1: Check for receive of a zero window probe, record the duration for
	//         probe to be sent.
	//
	// Advertize zero window to the dut.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), WindowSize: tb.Uint16(0)})

	// Expected sequence number of the zero window probe.
	probeSeq := tb.Uint32(uint32(*conn.RemoteSeqNum() - 1))
	// Expected ack number of the ACK for the probe.
	ackProbe := tb.Uint32(uint32(*conn.RemoteSeqNum()))

	// Expect there are no zero-window probes sent until there is data to be sent out
	// from the dut.
	if _, err := conn.ExpectData(&tb.TCP{SeqNum: probeSeq}, nil, time.Second); err == nil {
		t.Fatalf("unexpected a packet with sequence number %v: %s", probeSeq, err)
	}

	start := time.Now()
	// Ask the dut to send out data.
	dut.Send(acceptFd, sampleData, 0)
	// Expect zero-window probe from the dut.
	if _, err := conn.ExpectData(&tb.TCP{SeqNum: probeSeq}, nil, time.Second); err != nil {
		t.Fatalf("expected a packet with sequence number %v: %s", probeSeq, err)
	}
	// Record the duration for first probe, the dut sends the zero window probe after
	// a retransmission time interval.
	startProbeDuration := time.Now().Sub(start)

	// Test 2: Check if the dut recovers on advertizing non-zero receive window.
	//         and sends out the sample payload after the send window opens.
	//
	// Advertize non-zero window to the dut and ack the zero window probe.
	conn.Send(tb.TCP{AckNum: ackProbe, Flags: tb.Uint8(header.TCPFlagAck)})
	// Expect the dut to recover and transmit data.
	if _, err := conn.ExpectData(&tb.TCP{SeqNum: ackProbe}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
	}

	// Test 3: Sanity check for dut's processing of a similar probe it sent.
	//         Check if the dut responds as we do for a similar probe sent to it.
	//         Basically with sequence number to one byte behind the unacknowledged
	//         sequence number.
	p := tb.Uint32(uint32(*conn.LocalSeqNum()))
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), SeqNum: tb.Uint32(uint32(*conn.LocalSeqNum() - 1))})
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), AckNum: p}, nil, time.Second); err != nil {
		t.Fatalf("expected a packet with ack number: %d: %s", p, err)
	}

	// Test 4: Check for the dut to keep the connection alive as long as the
	//         zero window probes are acknowledged.
	//         Check if the zero window probes are sent at exponentially
	//         increasing intervals. The timeout intervals are function
	//         of the recorded first zero probe transmission duration.
	//
	// Advertize zero receive window again.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), WindowSize: tb.Uint16(0)})
	probeSeq = tb.Uint32(uint32(*conn.RemoteSeqNum() - 1))
	ackProbe = tb.Uint32(uint32(*conn.RemoteSeqNum()))

	// Ask the dut to send out data.
	dut.Send(acceptFd, sampleData, 0)
	// Expect the dut to keep the connection alive as long as the remote is
	// acknowledging the zero-window probes.
	for i := 0; i < 5; i++ {
		start := time.Now()
		// Expect zero-window probe with a timeout which is a function of the typical
		// first retransmission time. The retransmission times is supposed to
		// exponentially increase.
		if _, err := conn.ExpectData(&tb.TCP{SeqNum: probeSeq}, nil, (2<<i)*startProbeDuration); err != nil {
			t.Fatalf("expected a probe with sequence number %v: loop %d", probeSeq, i)
		}
		// Check if the probes came at exponentially increasing intervals.
		if p := time.Since(start); p < ((1<<i)-1)*startProbeDuration {
			t.Fatalf("zero probe came sooner interval %d probe %d\n", p, i)
		}
		// Acknowledge the zero-window probes from the dut.
		conn.Send(tb.TCP{AckNum: ackProbe, Flags: tb.Uint8(header.TCPFlagAck), WindowSize: tb.Uint16(0)})
	}
	// Advertize non-zero window.
	conn.Send(tb.TCP{AckNum: ackProbe, Flags: tb.Uint8(header.TCPFlagAck)})
	// Expect the dut to recover and transmit data.
	if _, err := conn.ExpectData(&tb.TCP{SeqNum: ackProbe}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
	}

	// Test 5: Check if the dut times out the connection by honoring usertimeout
	//         when the dut is sending zero-window probes.
	//
	// Reduce the retransmit timeout.
	dut.SetSockOptInt(acceptFd, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int32(startProbeDuration.Milliseconds()))
	// Advertize zero window again.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), WindowSize: tb.Uint16(0)})
	// Ask the dut to send out data.
	dut.Send(acceptFd, sampleData, 0)

	// Wait for the connection to timeout after multiple zero-window probe retransmissions.
	time.Sleep(8 * startProbeDuration)

	// Expect the connection to have timed out and closed which would cause the dut
	// to reply with a RST to the ACK we send.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagRst)}, nil, time.Second); err != nil {
		t.Fatalf("expected a TCP RST")
	}
}
