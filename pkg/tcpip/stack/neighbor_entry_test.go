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

package stack

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	entryTestNetNumber tcpip.NetworkProtocolNumber = math.MaxUint32

	entryTestNICID tcpip.NICID = 1
	entryTestAddr1             = tcpip.Address("\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
	entryTestAddr2             = tcpip.Address("\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")

	entryTestLinkAddr1 = tcpip.LinkAddress("\x0a\x00\x00\x00\x00\x01")
	entryTestLinkAddr2 = tcpip.LinkAddress("\x0a\x00\x00\x00\x00\x02")

	// entryTestNetDefaultMTU is the MTU, in bytes, used throughout the tests,
	// except where another value is explicitly used. It is chosen to match the
	// MTU of loopback interfaces on Linux systems.
	entryTestNetDefaultMTU = 65536

	entryTestMaxDuration = time.Duration(math.MaxInt64) // approximately 290 years
)

// The following unit tests exercise every state transition and verify its
// behavior with RFC 4681.
//
// | From       | To         | Cause                                      | Action          | Event   |
// | ========== | ========== | ========================================== | =============== | ======= |
// | Unknown    | Unknown    | Confirmation w/ unknown address            |                 | Added   |
// | Unknown    | Incomplete | Packet queued to unknown address           | Send probe      | Added   |
// | Unknown    | Stale      | Probe w/ unknown address                   |                 | Added   |
// | Incomplete | Incomplete | Retransmit timer expired                   | Send probe      | Changed |
// | Incomplete | Reachable  | Solicited confirmation                     | Notify wakers   | Changed |
// | Incomplete | Stale      | Unsolicited confirmation                   | Notify wakers   | Changed |
// | Incomplete | Failed     | Max probes sent without reply              | Notify wakers   | Removed |
// | Reachable  | Reachable  | Confirmation w/ different isRouter flag    | Update IsRouter |         |
// | Reachable  | Stale      | Reachable timer expired                    |                 | Changed |
// | Reachable  | Stale      | Probe or confirmation w/ different address |                 | Changed |
// | Stale      | Reachable  | Solicited override confirmation            | Update LinkAddr | Changed |
// | Stale      | Stale      | Override confirmation                      | Update LinkAddr | Changed |
// | Stale      | Stale      | Probe w/ different address                 | Update LinkAddr | Changed |
// | Stale      | Delay      | Packet sent                                |                 | Changed |
// | Delay      | Reachable  | Upper-layer confirmation                   |                 | Changed |
// | Delay      | Reachable  | Solicited override confirmation            | Update LinkAddr | Changed |
// | Delay      | Stale      | Probe or confirmation w/ different address |                 | Changed |
// | Delay      | Probe      | Delay timer expired                        | Send probe      | Changed |
// | Probe      | Reachable  | Solicited override confirmation            | Update LinkAddr | Changed |
// | Probe      | Reachable  | Solicited confirmation w/ same address     | Notify wakers   | Changed |
// | Probe      | Stale      | Probe or confirmation w/ different address |                 | Changed |
// | Probe      | Probe      | Retransmit timer expired                   | Send probe      | Changed |
// | Probe      | Failed     | Max probes sent without reply              | Notify wakers   | Removed |
// | Failed     | Unknown    | Unreachability timer expired               |                 |         |

type testEntryEventType uint8

const (
	entryTestAdded testEntryEventType = iota
	entryTestChanged
	entryTestRemoved
)

func (t testEntryEventType) String() string {
	switch t {
	case entryTestAdded:
		return "add"
	case entryTestChanged:
		return "change"
	case entryTestRemoved:
		return "remove"
	default:
		return fmt.Sprintf("unknown (%d)", t)
	}
}

// Fields are exported for use with cmp.Diff.
type testEntryEventInfo struct {
	EventType testEntryEventType
	NICID     tcpip.NICID
	Addr      tcpip.Address
	LinkAddr  tcpip.LinkAddress
	State     NeighborState
	UpdatedAt time.Time
}

func (e testEntryEventInfo) String() string {
	return fmt.Sprintf("%s event for NIC #%d, addr=%q, linkAddr=%q, state=%q", e.EventType, e.NICID, e.Addr, e.LinkAddr, e.State)
}

// testNUDDispatcher implements NUDDispatcher to validate the dispatching of
// events upon certain NUD state machine events.
type testNUDDispatcher struct {
	// C is where events are queued
	C chan testEntryEventInfo
}

func newTestNUDDispatcher() *testNUDDispatcher {
	return &testNUDDispatcher{
		C: make(chan testEntryEventInfo, 4*neighborCacheSize),
	}
}

var _ NUDDispatcher = (*testNUDDispatcher)(nil)

func (d *testNUDDispatcher) queueEvent(e testEntryEventInfo) {
	if d.C == nil {
		return
	}
	if len(d.C) == cap(d.C) {
		panic("NUD event channel full")
	}
	d.C <- e
}

func (d *testNUDDispatcher) OnNeighborAdded(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState, updatedAt time.Time) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestAdded,
		NICID:     nicID,
		Addr:      addr,
		LinkAddr:  linkAddr,
		State:     state,
		UpdatedAt: updatedAt,
	})
}

func (d *testNUDDispatcher) OnNeighborChanged(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState, updatedAt time.Time) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestChanged,
		NICID:     nicID,
		Addr:      addr,
		LinkAddr:  linkAddr,
		State:     state,
		UpdatedAt: updatedAt,
	})
}

func (d *testNUDDispatcher) OnNeighborRemoved(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState, updatedAt time.Time) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestRemoved,
		NICID:     nicID,
		Addr:      addr,
		LinkAddr:  linkAddr,
		State:     state,
		UpdatedAt: updatedAt,
	})
}

func (d *testNUDDispatcher) expectEvents(t *testing.T, events []testEntryEventInfo) {
	t.Helper()
	for _, wantEvent := range events {
		select {
		case gotEvent := <-d.C:
			if diff := cmp.Diff(gotEvent, wantEvent, cmpopts.IgnoreFields(wantEvent, "UpdatedAt")); diff != "" {
				t.Errorf("invalid event received (-got, +want):\n%s", diff)
			}
		case <-time.After(time.Second):
			t.Fatalf("event not dispatched after one second:\n%s", wantEvent)
		}
	}
	d.expectNoMoreEvents(t)
}

func (d *testNUDDispatcher) expectNoMoreEvents(t *testing.T) {
	t.Helper()
	if len(d.C) > 0 {
		message := fmt.Sprintf("expect no more events dispatched, got %d more:", len(d.C))
		close(d.C)
		for e := range d.C {
			message += "\n" + e.String()
		}
		t.Fatal(message)
	}
}

type entryTestLinkResolver struct {
	probes chan entryTestProbeInfo
}

var _ LinkAddressResolver = (*entryTestLinkResolver)(nil)

type entryTestProbeInfo struct {
	RemoteAddress     tcpip.Address
	RemoteLinkAddress tcpip.LinkAddress
	LocalAddress      tcpip.Address
}

// LinkAddressRequest sends a request for the LinkAddress of addr. Broadcasts
// to the local network if linkAddr is the zero value.
func (r *entryTestLinkResolver) LinkAddressRequest(addr, localAddr tcpip.Address, linkAddr tcpip.LinkAddress, linkEP LinkEndpoint) *tcpip.Error {
	p := entryTestProbeInfo{
		RemoteAddress:     addr,
		RemoteLinkAddress: linkAddr,
		LocalAddress:      localAddr,
	}

	select {
	case r.probes <- p:
		return nil
	default:
		return tcpip.ErrConnectionRefused
	}
}

// ResolveStaticAddress attempts to resolve address without sending requests.
// It either resolves the name immediately or returns the empty LinkAddress.
func (r *entryTestLinkResolver) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	return "", false
}

// LinkAddressProtocol returns the network protocol of the addresses this
// resolver can resolve.
func (r *entryTestLinkResolver) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return entryTestNetNumber
}

func (r *entryTestLinkResolver) expectNoMoreProbes(t *testing.T) {
	t.Helper()
	if len(r.probes) > 0 {
		t.Fatalf("expected no more probes sent, got %d more", len(r.probes))
	}
}

func (r *entryTestLinkResolver) expectProbes(t *testing.T, probes []entryTestProbeInfo) {
	t.Helper()
	for _, wantProbe := range probes {
		select {
		case gotProbe := <-r.probes:
			if got, want := gotProbe.RemoteAddress, wantProbe.RemoteAddress; got != want {
				t.Errorf("got RemoteAddress=%q, want=%q", string(got), string(want))
			}
			if got, want := gotProbe.RemoteLinkAddress, wantProbe.RemoteLinkAddress; got != want {
				t.Errorf("got RemoteLinkAddress=%q, want=%q", string(got), string(want))
			}
		case <-time.After(time.Second):
			t.Fatal("probe not sent within the last second")
		}
	}
	r.expectNoMoreProbes(t)
}

func entryTestSetup(c NUDConfigurations) (*neighborEntry, *testNUDDispatcher, *entryTestLinkResolver) {
	disp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, 4*neighborCacheSize),
	}
	linkRes := entryTestLinkResolver{
		probes: make(chan entryTestProbeInfo, 300),
	}
	nic := NIC{
		id:     entryTestNICID,
		linkEP: nil, // entryTestLinkResolver doesn't use a LinkEndpoint
		stack: &Stack{
			nudDisp: &disp,
		},
	}
	nic.mu.ndp = ndpState{
		nic:            &nic,
		defaultRouters: make(map[tcpip.Address]defaultRouterState),
	}
	nudState := NewNUDState(c)
	entry := newNeighborEntry(&nic, entryTestAddr1, entryTestAddr2, nudState, &linkRes)
	return entry, &disp, &linkRes
}

// TestEntryInitiallyUnknown verifies that the state of a newly created
// neighborEntry is Unknown.
func TestEntryInitiallyUnknown(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Unknown; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{})
	nudDisp.expectNoMoreEvents(t)
}

func TestEntryUnknownToUnknownWhenConfirmationWithUnknownAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Unknown; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{})
	nudDisp.expectNoMoreEvents(t)
}

func TestEntryUnknownToIncomplete(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})
	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
	})
}

func TestEntryUnknownToStale(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handleProbeLocked(entryTestLinkAddr1)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{})
	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	})
}

func TestEntryIncompleteToIncompleteDoesNotChangeUpdatedAt(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = 250 * time.Millisecond
	c.MaxMulticastProbes = 3
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	updatedAt := e.mu.neigh.UpdatedAt
	e.mu.Unlock()

	// Wait for the first two probes then verify that UpdatedAt did not change.
	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.UpdatedAt, updatedAt; got != want {
		t.Errorf("e.mu.neigh.UpdatedAt=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	// Wait for the transition to Failed then verify that UpdatedAt changed.
	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
	})

	e.mu.Lock()
	if got, notWant := e.mu.neigh.UpdatedAt, updatedAt; got == notWant {
		t.Errorf("expected e.mu.neigh.UpdatedAt to change, got=%q", got)
	}
	e.mu.Unlock()
}

func TestEntryIncompleteToReachable(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	})
}

func TestEntryIncompleteToReachableWithRouterFlag(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  true,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.isRouter, true; got != want {
		t.Errorf("e.mu.isRouter=%t, want=%t", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	})
}

func TestEntryIncompleteToStale(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	})
}

func TestEntryIncompleteToFailed(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = time.Microsecond
	c.MaxMulticastProbes = 3
	c.UnreachableTime = entryTestMaxDuration // don't transition out of Failed
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		// The Incomplete-to-Incomplete state transition is tested here by
		// verifying that 3 reachability probes were sent.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Failed; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

type testLocker struct{}

var _ sync.Locker = (*testLocker)(nil)

func (*testLocker) Lock()   {}
func (*testLocker) Unlock() {}

func TestEntryStaysReachableWhenConfirmationWithRouterFlag(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = time.Microsecond
	c.MaxMulticastProbes = 1
	c.BaseReachableTime = time.Duration(math.MaxInt64)
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  true,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.isRouter, true; got != want {
		t.Errorf("e.mu.isRouter=%t, want=%t", got, want)
	}
	e.nic.mu.ndp.defaultRouters[entryTestAddr1] = defaultRouterState{
		invalidationTimer: tcpip.NewCancellableTimer(&testLocker{}, func() {}),
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.isRouter, false; got != want {
		t.Errorf("e.mu.isRouter=%t, want=%t", got, want)
	}
	if _, ok := e.nic.mu.ndp.defaultRouters[entryTestAddr1]; ok {
		t.Errorf("unexpected defaultRouter for %s", entryTestAddr1)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryStaysReachableWhenProbeWithSameAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = time.Microsecond
	c.MaxMulticastProbes = 1
	c.BaseReachableTime = time.Duration(math.MaxInt64)
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr1)
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	})
}

func TestEntryReachableToStaleWhenTimeout(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = time.Microsecond
	c.MaxMulticastProbes = 1
	c.MaxUnicastProbes = 3
	c.BaseReachableTime = minimumBaseReachableTime
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryReachableToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration
	c.BaseReachableTime = entryTestMaxDuration // disable Reachable timer
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryReachableToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration
	c.BaseReachableTime = entryTestMaxDuration // disable Reachable timer
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryReachableToStaleWhenConfirmationWithDifferentAddressAndOverride(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration
	c.BaseReachableTime = entryTestMaxDuration // disable Reachable timer
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryStaysStaleWhenProbeWithSameAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr1)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	})
}

func TestEntryStaleToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Reachable,
		},
	})
}

func TestEntryStaleToStaleWhenOverrideConfirmation(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	})
}

func TestEntryStaleToStaleWhenProbeUpdateAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	})
}

func TestEntryStaleToDelay(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration     // only send one probe
	c.DelayFirstProbeTime = entryTestMaxDuration // only send one probe
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
	})
}

func TestEntryDelayToReachableWhenUpperLevelConfirmation(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration     // only send one probe
	c.DelayFirstProbeTime = entryTestMaxDuration // stay in Delay
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleUpperLevelConfirmationLocked()
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	})
}

func TestEntryDelayToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration     // only send one probe
	c.DelayFirstProbeTime = entryTestMaxDuration // stay in Delay
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Reachable,
		},
	})
}

func TestEntryStaysDelayWhenOverrideConfirmationWithSameAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration     // only send one probe
	c.DelayFirstProbeTime = entryTestMaxDuration // stay in Delay
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
	})
}

func TestEntryDelayToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration     // only send one probe
	c.DelayFirstProbeTime = entryTestMaxDuration // stay in Delay
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	})
}

func TestEntryDelayToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration     // only send one probe
	c.DelayFirstProbeTime = entryTestMaxDuration // stay in Delay
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	})
}

func TestEntryDelayToProbe(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	c.DelayFirstProbeTime = time.Microsecond
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
	})

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryProbeToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	c.DelayFirstProbeTime = time.Microsecond // transition to Probe almost immediately
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryProbeToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	c.DelayFirstProbeTime = time.Microsecond // transition to Probe almost immediately
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryStaysProbeWhenOverrideConfirmationWithSameAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	c.DelayFirstProbeTime = time.Microsecond // transition to Probe almost immediately
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	})
}

func TestEntryProbeToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	c.DelayFirstProbeTime = time.Microsecond // transition to Probe almost immediately
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Reachable,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryProbeToReachableWhenSolicitedConfirmationWithSameAddress(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = entryTestMaxDuration // only send one probe
	c.DelayFirstProbeTime = time.Microsecond // transition to Probe almost immediately
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryProbeToFailed(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = time.Microsecond
	c.MaxMulticastProbes = 3
	c.MaxUnicastProbes = 3
	c.DelayFirstProbeTime = time.Microsecond // transition to Probe almost immediately
	c.UnreachableTime = entryTestMaxDuration // don't transition out of Failed
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
		// The next three probe are caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
	})
	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	})

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Failed; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	time.Sleep(time.Second)
	linkRes.expectNoMoreProbes(t)
}

func TestEntryFailedToUnknown(t *testing.T) {
	t.Parallel()
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = time.Microsecond
	c.MaxMulticastProbes = 3
	c.MaxUnicastProbes = 3
	c.DelayFirstProbeTime = time.Microsecond // transition to Probe almost immediately
	c.UnreachableTime = time.Microsecond     // transition to Unknown almost immediately
	e, nudDisp, linkRes := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked(linkRes)
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked(linkRes)
	e.mu.Unlock()

	linkRes.expectProbes(t, []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
		},
		// The next three probe are caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
		},
	})
	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	})

	// Since there are no events or probes sent out in the transition from Failed
	// to Unknown, the test is forced to wait a set amount.
	time.Sleep(time.Second)

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Unknown; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q after 1ms", got, want)
	}
	e.mu.Unlock()
}
