// Copyright 2019 The gVisor Authors.
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
	"bytes"
	"encoding/binary"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

func newTestNeighborCache(nudDisp NUDDispatcher, config NUDConfigurations) *neighborCache {
	c := &neighborCache{
		nic: &NIC{
			stack: &Stack{
				nudDisp: nudDisp,
			},
			id:     1,
			linkEP: &testLinkEndpoint{},
		},
		state: NewNUDState(config.resetInvalidFields()),
	}
	c.mu.cache = make(map[tcpip.Address]*neighborEntry, neighborCacheSize)
	return c
}

// testEntryStore generates a default set of IP to MAC addresses used for
// testing and allows for modification of link addresses to simulate a new
// neighbor in the network reusing an IP address.
type testEntryStore struct {
	mu      sync.RWMutex
	entries map[tcpip.Address]NeighborEntry
}

func toAddress(i int) tcpip.Address {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint8(1))
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, uint16(i))
	return tcpip.Address(buf.String())
}

func toLinkAddress(i int) tcpip.LinkAddress {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint8(1))
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, uint32(i))
	return tcpip.LinkAddress(buf.String())
}

func newTestEntryStore() *testEntryStore {
	entries := make(map[tcpip.Address]NeighborEntry)
	for i := 0; i < 4*neighborCacheSize; i++ {
		addr := toAddress(i)
		linkAddr := toLinkAddress(i)
		entries[addr] = NeighborEntry{
			Addr:      addr,
			LocalAddr: tcpip.Address("LocalAddr"),
			LinkAddr:  linkAddr,
		}
	}
	return &testEntryStore{
		entries: entries,
	}
}

func (s *testEntryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *testEntryStore) Entry(i int) NeighborEntry {
	addr := toAddress(i)
	entry, _ := s.EntryByAddr(tcpip.Address(addr))
	return entry
}

func (s *testEntryStore) EntryByAddr(addr tcpip.Address) (NeighborEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[addr]
	return entry, ok
}

func (s *testEntryStore) Entries() []NeighborEntry {
	entries := make([]NeighborEntry, 0, len(s.entries))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := 0; i < 4*neighborCacheSize; i++ {
		addr := toAddress(i)
		if entry, ok := s.entries[tcpip.Address(addr)]; ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

func (s *testEntryStore) Set(i int, linkAddr tcpip.LinkAddress) {
	addr := toAddress(i)
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.entries[tcpip.Address(addr)]; ok {
		entry.LinkAddr = linkAddr
		s.entries[tcpip.Address(addr)] = entry
	}
}

// testLinkAddressResolver implements LinkAddressResolver to emulate sending a
// neighbor probe.
type testLinkAddressResolver struct {
	handler              NUDHandler
	entries              *testEntryStore
	delay                time.Duration
	onLinkAddressRequest func()
}

var _ LinkAddressResolver = (*testLinkAddressResolver)(nil)

func (r *testLinkAddressResolver) LinkAddressRequest(addr, localAddr tcpip.Address, linkAddr tcpip.LinkAddress, linkEP LinkEndpoint) *tcpip.Error {
	time.AfterFunc(r.delay, func() { r.fakeRequest(addr) })
	if f := r.onLinkAddressRequest; f != nil {
		f()
	}
	return nil
}

func (r *testLinkAddressResolver) fakeRequest(addr tcpip.Address) {
	if entry, ok := r.entries.EntryByAddr(addr); ok {
		r.handler.HandleConfirmation(entry.Addr, entry.LinkAddr, ReachabilityConfirmationFlags{
			Solicited: true,
			Override:  false,
			IsRouter:  false,
		})
	}
}

func (*testLinkAddressResolver) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if addr == "broadcast" {
		return "mac_broadcast", true
	}
	return "", false
}

func (*testLinkAddressResolver) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return 1
}

func getBlocking(n *neighborCache, e NeighborEntry, linkRes LinkAddressResolver) (NeighborEntry, *tcpip.Error) {
	w := sleep.Waker{}
	s := sleep.Sleeper{}
	s.AddWaker(&w, 123)
	defer s.Done()

	for {
		if got, _, err := n.entry(e.Addr, e.LocalAddr, linkRes, &w); err != tcpip.ErrWouldBlock {
			return got, err
		}
		s.Fetch(true)
	}
}

// testLinkEndpoint implements LinkEndpoint to validate the sending of probes
// and advertisements upon each certain NUD events.
type testLinkEndpoint struct{}

var _ LinkEndpoint = (*testLinkEndpoint)(nil)

func (*testLinkEndpoint) MTU() uint32 {
	return 1500
}

func (*testLinkEndpoint) Capabilities() LinkEndpointCapabilities {
	return CapabilityResolutionRequired
}

func (*testLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (*testLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (*testLinkEndpoint) WritePacket(*Route, *GSO, tcpip.NetworkProtocolNumber, PacketBuffer) *tcpip.Error {
	return nil
}

func (*testLinkEndpoint) WritePackets(*Route, *GSO, PacketBufferList, tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	return 0, nil
}

func (*testLinkEndpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	return nil
}

func (*testLinkEndpoint) Attach(NetworkDispatcher) {}

func (*testLinkEndpoint) IsAttached() bool {
	return true
}

func (*testLinkEndpoint) Wait() {}

type entryEvent struct {
	NICID    tcpip.NICID
	Address  tcpip.Address
	LinkAddr tcpip.LinkAddress
	State    NeighborState
}

func TestCacheGetConfig(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	neigh := newTestNeighborCache(&nudDisp, c)

	if got, want := neigh.config(), c; got != want {
		t.Errorf("neigh.config()=%+v, want %+v", got, want)
	}

	nudDisp.expectNoMoreEvents(t)
}

func TestCacheSetConfig(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	neigh := newTestNeighborCache(&nudDisp, c)

	c.BaseReachableTime = time.Duration(math.MaxInt64) // approximately 292 years
	neigh.setConfig(c)

	if got, want := neigh.config(), c; got != want {
		t.Errorf("neigh.config()=%+v, want %+v", got, want)
	}

	nudDisp.expectNoMoreEvents(t)
}

func TestCacheEntry(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	neigh := newTestNeighborCache(&nudDisp, c)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
	}

	a := store.Entry(0)
	_, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})

	_, _, err = neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	nudDisp.expectNoMoreEvents(t)
}

func TestCacheRemoveEntry(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	neigh := newTestNeighborCache(&nudDisp, c)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
	}

	a := store.Entry(0)
	_, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})

	neigh.removeEntry(a.Addr)

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})

	_, _, err = neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
}

type testContext struct {
	t       *testing.T
	neigh   *neighborCache
	store   *testEntryStore
	linkRes *testLinkAddressResolver
	nudDisp *testNUDDispatcher
}

func newTestContext(t *testing.T, c NUDConfigurations) testContext {
	nudDisp := &testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	neigh := newTestNeighborCache(nudDisp, c)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
	}

	return testContext{
		t:       t,
		neigh:   neigh,
		store:   store,
		linkRes: linkRes,
		nudDisp: nudDisp,
	}
}

type overflowOptions struct {
	expectedDynamicEntryCount int
	startAtEntryIndex         int
}

func (c *testContext) overflowCache(opts overflowOptions) {
	// Fill the neighbor cache to capacity to verify the LRU eviction strategy is
	// working properly after the entry removal.
	offset := opts.startAtEntryIndex - opts.expectedDynamicEntryCount
	for i := opts.startAtEntryIndex; i < neighborCacheSize+offset; i++ {
		a := c.store.Entry(i)
		_, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
		if err != tcpip.ErrWouldBlock {
			c.t.Errorf("fill %d, neigh.entry(%q) should block, got %v", i, a.Addr, err)
		}
		c.nudDisp.expectEvents(c.t, []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      a.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      a.Addr,
				LinkAddr:  a.LinkAddr,
				State:     Reachable,
			},
		})
	}

	// Keep adding more entries
	for i := neighborCacheSize + offset; i < c.store.Len(); i++ {
		a := c.store.Entry(i)
		_, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
		if err != tcpip.ErrWouldBlock {
			c.t.Errorf("overflow %d, neigh.entry(%q) should block, got %v", i, a.Addr, err)
		}
		removedEntry := c.store.Entry(i - neighborCacheSize)
		c.nudDisp.expectEvents(c.t, []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Addr:      removedEntry.Addr,
				LinkAddr:  removedEntry.LinkAddr,
				State:     Reachable,
			},
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      a.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      a.Addr,
				LinkAddr:  a.LinkAddr,
				State:     Reachable,
			},
		})
	}

	// Expect to find only the most recent entries.
	for i := c.store.Len() - neighborCacheSize; i < c.store.Len(); i++ {
		a := c.store.Entry(i)
		e, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
		if err != nil {
			c.t.Errorf("check %d, neigh.entry(%q)=%q, got error: %v", i, a.Addr, e.LinkAddr, err)
		}
		if e.LinkAddr != a.LinkAddr {
			c.t.Errorf("check %d, neigh.entry(%q)=%q, want %q", i, a.Addr, e.LinkAddr, a.LinkAddr)
		}
	}

	// The earliest entries should no longer be in the cache.
	entries := c.neigh.entries()
	entryByAddr := mapByAddr(c.t, entries)
	for i := opts.startAtEntryIndex; i < c.store.Len()-neighborCacheSize; i++ {
		addr := c.store.Entry(i).Addr
		if _, ok := entryByAddr[addr]; ok {
			c.t.Errorf("check %d, neigh.entry(%q), got exists, want nonexistent", i, addr)
		}
	}
	c.nudDisp.expectNoMoreEvents(c.t)
}

// TestCacheOverflow verifies that the LRU cache eviction strategy respects the
// dynamic entry count.
func TestCacheOverflow(t *testing.T) {
	t.Parallel()
	nudConfig := DefaultNUDConfigurations()
	c := newTestContext(t, nudConfig)
	c.overflowCache(overflowOptions{
		startAtEntryIndex:         0,
		expectedDynamicEntryCount: 0,
	})
}

// TestCacheRemoveEntryThenOverflow verifies that the LRU cache eviction
// strategy respects the dynamic entry count when an entry is removed.
func TestCacheRemoveEntryThenOverflow(t *testing.T) {
	t.Parallel()

	nudConfig := DefaultNUDConfigurations()
	c := newTestContext(t, nudConfig)

	// Add a dynamic entry
	a := c.store.Entry(0)
	_, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		c.t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	c.nudDisp.expectEvents(c.t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})

	// Remove the entry
	c.neigh.removeEntry(a.Addr)
	c.nudDisp.expectEvents(c.t, []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})

	c.overflowCache(overflowOptions{
		startAtEntryIndex:         0,
		expectedDynamicEntryCount: 0,
	})
}

// TestCacheRemoveStaticEntryThenOverflow verifies that the LRU cache eviction
// strategy respects the dynamic entry count when a static entry is added then
// removed. In this case, the dynamic entry count shouldn't have been touched.
func TestCacheRemoveStaticEntryThenOverflow(t *testing.T) {
	t.Parallel()

	nudConfig := DefaultNUDConfigurations()
	c := newTestContext(t, nudConfig)

	// Add a static entry
	a := c.store.Entry(0)
	staticLinkAddr := a.LinkAddr + "static"
	c.neigh.addStaticEntry(a.Addr, staticLinkAddr)
	c.nudDisp.expectEvents(c.t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  staticLinkAddr,
			State:     Static,
		},
	})

	// Remove the static entry that was just added
	c.neigh.removeEntry(a.Addr)
	c.nudDisp.expectEvents(c.t, []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  staticLinkAddr,
			State:     Static,
		},
	})

	c.overflowCache(overflowOptions{
		startAtEntryIndex:         0,
		expectedDynamicEntryCount: 0,
	})
}

// TestCacheOverwriteWithStaticEntryThenOverflow verifies that the LRU cache
// eviction strategy keeps count of the dynamic entry count when an entry is
// overwritten by a static entry. Static entries should not count towards the
// size of the LRU cache.
func TestCacheOverwriteWithStaticEntryThenOverflow(t *testing.T) {
	t.Parallel()

	nudConfig := DefaultNUDConfigurations()
	c := newTestContext(t, nudConfig)

	// Add a dynamic entry
	a := c.store.Entry(0)
	_, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		c.t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	c.nudDisp.expectEvents(c.t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})

	// Override the entry with a static one using the same address
	staticLinkAddr := a.LinkAddr + "static"
	c.neigh.addStaticEntry(a.Addr, staticLinkAddr)
	c.nudDisp.expectEvents(c.t, []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  staticLinkAddr,
			State:     Static,
		},
	})

	c.overflowCache(overflowOptions{
		startAtEntryIndex:         1,
		expectedDynamicEntryCount: 0,
	})

	// The static entry should be in the cache.
	e, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
	if err != nil {
		c.t.Errorf("expected static neighbor entry for %q, got error: %v", a.Addr, err)
	}
	if got, want := e.LinkAddr, staticLinkAddr; got != want {
		c.t.Errorf("got e.LinkAddr=%q, want %q", got, want)
	}
	if got, want := e.State, Static; got != want {
		c.t.Errorf("got e.State=%q, want %q", got, want)
	}

	c.nudDisp.expectNoMoreEvents(t)
}

func TestCacheNotifiesWaker(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	neigh := newTestNeighborCache(&nudDisp, NUDConfigurations{
		BaseReachableTime: time.Duration(math.MaxInt64), // approximately 292 years
	})
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   time.Millisecond,
	}

	w := sleep.Waker{}
	s := sleep.Sleeper{}
	const wakerID = 1
	s.AddWaker(&w, wakerID)

	a := store.Entry(0)
	_, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, &w)
	if err != tcpip.ErrWouldBlock {
		t.Fatalf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	if doneCh == nil {
		t.Fatalf("expected channel from neigh.entry(%q), got none", a.Addr)
	}

	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatalf("channel not notified after 1 second")
	}

	id, ok := s.Fetch(false /* block */)
	if !ok {
		t.Error("expected waker to be notified")
	}
	if id != wakerID {
		t.Errorf("got s.Fetch(false)=%d, want=%d", id, wakerID)
	}

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})
}

func TestCacheRemoveWaker(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	neigh := newTestNeighborCache(&nudDisp, NUDConfigurations{
		BaseReachableTime: time.Duration(math.MaxInt64), // approximately 292 years
	})
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   time.Millisecond,
	}

	w := sleep.Waker{}
	s := sleep.Sleeper{}
	const wakerID = 1
	s.AddWaker(&w, wakerID)

	a := store.Entry(0)
	_, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, &w)
	if err != tcpip.ErrWouldBlock {
		t.Fatalf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	if doneCh == nil {
		t.Fatalf("expected channel from neigh.entry(%q), got none", a.Addr)
	}

	neigh.removeWaker(a.Addr, &w)

	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatalf("channel not notified after 1 second")
	}

	id, ok := s.Fetch(false /* block */)
	if ok {
		t.Error("unexpected notification from waker")
	}
	if id == wakerID {
		t.Errorf("got s.Fetch(false)=%d, want anything but %d", id, wakerID)
	}

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})
}

func TestCacheAddStaticEntry(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	neigh := newTestNeighborCache(&nudDisp, c)

	neigh.addStaticEntry(entryTestAddr1, entryTestLinkAddr1)
	e, _, err := neigh.entry(entryTestAddr1, "", nil, nil)
	if err != nil {
		t.Errorf("neigh.entry(%q) returned error %s", entryTestAddr1, err)
	}
	if got, want := e.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("got neigh.entry(%q).LinkAddr=%q, want %q", entryTestAddr1, got, want)
	}

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Static,
		},
	})
}

func TestCacheRemoveStaticEntry(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	neigh := newTestNeighborCache(&nudDisp, c)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
	}

	a := store.Entry(0)
	neigh.addStaticEntry(a.Addr, a.LinkAddr)
	neigh.removeEntry(a.Addr)

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Static,
		},
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Static,
		},
	})

	_, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
}

func TestCacheStaticEntryOverridesDynamicEntry(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	neigh := newTestNeighborCache(&nudDisp, c)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
	}

	// Add a dynamic entry.
	a := store.Entry(0)
	_, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})

	e, _, err := neigh.entry(a.Addr, "", nil, nil)
	if err != nil {
		t.Errorf("neigh.entry(%q) returned error %s", a.Addr, err)
	}

	a.State = Reachable
	if diff := cmp.Diff(e, a, cmpopts.IgnoreFields(a, "UpdatedAt")); diff != "" {
		t.Errorf("invalid neighbor entry received (-got, +want):\n%s", diff)
	}

	// Replace the dynamic entry with a static one.
	neigh.addStaticEntry(a.Addr, entryTestLinkAddr1)

	e, _, err = neigh.entry(a.Addr, "", nil, nil)
	if err != nil {
		t.Errorf("neigh.entry(%q) returned error %s", a.Addr, err)
	}

	wantEntry := NeighborEntry{
		Addr:     a.Addr,
		LinkAddr: entryTestLinkAddr1,
		State:    Static,
	}
	if diff := cmp.Diff(e, wantEntry, cmpopts.IgnoreFields(a, "UpdatedAt")); diff != "" {
		t.Errorf("invalid neighbor entry received (-got, +want):\n%s", diff)
	}

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  entryTestLinkAddr1,
			State:     Static,
		},
	})
}

func TestCacheClear(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	neigh := newTestNeighborCache(&nudDisp, c)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
	}

	// Add a dynamic entry.
	a := store.Entry(0)
	_, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})

	// Add a static entry.
	neigh.addStaticEntry(entryTestAddr1, entryTestLinkAddr1)

	nudDisp.expectEvents(t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Static,
		},
	})

	// Clear shoud remove both dynamic and static entries.
	neigh.clear()

	// Remove events dispatched from clear() have no deterministic order.
	events := make(map[tcpip.Address]testEntryEventInfo)
	for _, e := range []testEntryEventInfo{<-nudDisp.C, <-nudDisp.C} {
		if existing, ok := events[e.Addr]; ok {
			if diff := cmp.Diff(existing, e); diff != "" {
				t.Fatalf("duplicate event found (-existing +got):\n%s", diff)
			} else {
				t.Fatalf("exact event duplicate found for %s", e)
			}
		}
		events[e.Addr] = e
	}

	gotEvent, ok := events[a.Addr]
	if !ok {
		t.Fatalf("expected event with Addr=%q", a.Addr)
	}

	wantEvent := testEntryEventInfo{
		EventType: entryTestRemoved,
		NICID:     1,
		Addr:      a.Addr,
		LinkAddr:  a.LinkAddr,
		State:     Reachable,
	}
	if diff := cmp.Diff(gotEvent, wantEvent, cmpopts.IgnoreFields(wantEvent, "UpdatedAt")); diff != "" {
		t.Errorf("invalid event received (-got, +want):\n%s", diff)
	}

	gotEvent, ok = events[entryTestAddr1]
	if !ok {
		t.Fatalf("expected event with Addr=%q", a.Addr)
	}

	wantEvent = testEntryEventInfo{
		EventType: entryTestRemoved,
		NICID:     1,
		Addr:      entryTestAddr1,
		LinkAddr:  entryTestLinkAddr1,
		State:     Static,
	}
	if diff := cmp.Diff(gotEvent, wantEvent, cmpopts.IgnoreFields(wantEvent, "UpdatedAt")); diff != "" {
		t.Errorf("invalid event received (-got, +want):\n%s", diff)
	}

	nudDisp.expectNoMoreEvents(t)
}

func mapByAddr(t *testing.T, entries []NeighborEntry) map[tcpip.Address]NeighborEntry {
	t.Helper()
	entryByAddr := make(map[tcpip.Address]NeighborEntry)

	for _, e := range entries {
		if existing, ok := entryByAddr[e.Addr]; ok {
			if diff := cmp.Diff(existing, e); diff != "" {
				t.Fatalf("duplicate neighbor entry found (-existing +got):\n%s", diff)
			} else {
				t.Fatalf("exact neighbor entry duplicate found:\n%s", e)
			}
		}
		entryByAddr[e.Addr] = e
	}

	return entryByAddr
}

// TestCacheClearThenOverflow verifies that the LRU cache eviction strategy
// keeps count of the dynamic entry count when all entries are cleared.
func TestCacheClearThenOverflow(t *testing.T) {
	t.Parallel()

	nudConfig := DefaultNUDConfigurations()
	c := newTestContext(t, nudConfig)

	// Add a dynamic entry
	a := c.store.Entry(0)
	_, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		c.t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	c.nudDisp.expectEvents(c.t, []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})

	// Clear the cache.
	c.neigh.clear()
	c.nudDisp.expectEvents(c.t, []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	})

	c.overflowCache(overflowOptions{
		startAtEntryIndex:         0,
		expectedDynamicEntryCount: 0,
	})
}

func TestCacheKeepFrequentlyUsed(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	c.BaseReachableTime = time.Duration(math.MaxInt64) // approximately 292 years
	neigh := newTestNeighborCache(&nudDisp, c)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
	}

	frequentlyUsedEntry := store.Entry(0)

	// Fill the neighbor cache to capacity
	for i := 0; i < neighborCacheSize; i++ {
		a := store.Entry(i)
		_, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
		if doneCh != nil && err == tcpip.ErrWouldBlock {
			<-doneCh
		} else {
			t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
		}
		nudDisp.expectEvents(t, []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      a.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      a.Addr,
				LinkAddr:  a.LinkAddr,
				State:     Reachable,
			},
		})
	}
	// Keep adding more entries
	for i := neighborCacheSize; i < store.Len(); i++ {
		// Periodically refresh the frequently used entry
		if i%(neighborCacheSize/2) == 0 {
			_, _, err := neigh.entry(frequentlyUsedEntry.Addr, frequentlyUsedEntry.LocalAddr, linkRes, nil)
			if err != nil {
				t.Errorf("got error while refreshing recently used entry: %v", err)
			}
		}

		a := store.Entry(i)
		_, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
		if doneCh != nil && err == tcpip.ErrWouldBlock {
			<-doneCh
		} else {
			t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
		}
		removedEntry := store.Entry(i - neighborCacheSize + 1)
		nudDisp.expectEvents(t, []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Addr:      removedEntry.Addr,
				LinkAddr:  removedEntry.LinkAddr,
				State:     Reachable,
			},
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      a.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      a.Addr,
				LinkAddr:  a.LinkAddr,
				State:     Reachable,
			},
		})
	}
	// Expect to find only the most recent entries.
	for i := store.Len() - neighborCacheSize + 1; i < store.Len(); i++ {
		a := store.Entry(i)
		e, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
		if err != nil {
			t.Errorf("insert %d, neigh.entry(%q)=%q, got error: %v", i, a.Addr, e.LinkAddr, err)
		}
		if e.LinkAddr != a.LinkAddr {
			t.Errorf("insert %d, neigh.entry(%q)=%q, want %q", i, a.Addr, e.LinkAddr, a.LinkAddr)
		}
	}
	// The earliest entries should no longer be in the cache.
	entries := neigh.entries()
	entryByAddr := mapByAddr(t, entries)
	for i := 1; i < store.Len()-neighborCacheSize; i++ {
		addr := store.Entry(i).Addr
		if _, ok := entryByAddr[addr]; ok {
			t.Errorf("check %d, neigh.entry(%q), got exists, want nonexistent", i, addr)
		}
	}
	// The frequently used entry should be in the cache
	if _, ok := entryByAddr[frequentlyUsedEntry.Addr]; !ok {
		t.Error("expected frequently used entry to exist")
	}
	nudDisp.expectNoMoreEvents(t)
}

func TestCacheConcurrent(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{}
	neigh := newTestNeighborCache(&nudDisp, NUDConfigurations{
		BaseReachableTime: time.Duration(1<<63 - 1), // approximately 290 years
	})
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
	}

	storeEntries := store.Entries()
	var wg sync.WaitGroup
	for r := 0; r < 16; r++ {
		wg.Add(1)
		go func(r int) {
			for _, e := range storeEntries {
				_, doneCh, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil)
				if err != nil && err != tcpip.ErrWouldBlock {
					t.Errorf("neigh.entry(%q) want success or ErrWouldBlock, got %v", e.Addr, err)
				}
				if doneCh != nil {
					<-doneCh
				}
			}
			wg.Done()
		}(r)
	}
	wg.Wait()

	entries := make(map[tcpip.Address]NeighborEntry)
	for _, e := range neigh.entries() {
		entries[e.Addr] = e
	}

	// All goroutines add in the same order and add more values than
	// can fit in the cache, so our eviction strategy requires that
	// the last entry be present and the first be missing.
	e := store.Entry(store.Len() - 1)
	if entry, ok := entries[e.Addr]; ok {
		if entry.LinkAddr != e.LinkAddr {
			t.Errorf("neigh.entry(%q)=%q, want %q", e.Addr, entry.LinkAddr, e.LinkAddr)
		}
	} else {
		t.Errorf("neigh.entry(%q) does not exists, want exists", e.Addr)
	}

	e = store.Entry(0)
	if _, ok := entries[e.Addr]; ok {
		t.Errorf("neigh.entry(%q) exists, want does not exist", e.Addr)
	}
}

func TestCacheReplace(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	c.BaseReachableTime = time.Duration(math.MaxInt64) // approximately 292 years
	c.DelayFirstProbeTime = time.Millisecond
	c.RetransmitTimer = time.Millisecond
	neigh := newTestNeighborCache(&nudDisp, c)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
	}

	a := store.Entry(0)
	e, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != nil && doneCh != nil {
		<-doneCh
		if e2, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil); err != nil {
			t.Errorf("neigh.entry(%q) does not exist, got %v", a.Addr, err)
		} else {
			e = e2
		}
	} else {
		t.Errorf("neigh.entry(%q) should exist, got %v", a.Addr, err)
	}
	if e.LinkAddr != a.LinkAddr {
		t.Errorf("neigh.entry(%q).LinkAddr = %q, want %q", a.Addr, e.LinkAddr, a.LinkAddr)
	}

	updatedLinkAddr := a.LinkAddr + "2"
	store.Set(0, updatedLinkAddr)
	neigh.HandleConfirmation(a.Addr, updatedLinkAddr, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	e, doneCh, err = neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if doneCh != nil && err == tcpip.ErrWouldBlock {
		<-doneCh
	} else {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	e, _, err = neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != nil {
		t.Errorf("neigh.entry(%q) should exist, got %v", a.Addr, err)
	}
	if e.LinkAddr != updatedLinkAddr {
		t.Errorf("neigh.entry(%q).LinkAddr = %q, want %q", a.Addr, e.LinkAddr, updatedLinkAddr)
	}
}

func TestCacheResolution(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	c.BaseReachableTime = time.Duration(math.MaxInt64) // approximately 292 years
	neigh := newTestNeighborCache(&nudDisp, c)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
	}

	// Fill the neighbor cache to full capacity
	for i := 0; i < neighborCacheSize; i++ {
		e := store.Entry(i)
		got, err := getBlocking(neigh, e, linkRes)
		if err != nil {
			t.Errorf("neigh.entry(%q) got error: %v, want error: %v", e.Addr, err, tcpip.ErrWouldBlock)
		}
		if got.LinkAddr != e.LinkAddr {
			t.Errorf("neigh.entry(%q)=%q, want %q", e.Addr, got.LinkAddr, e.LinkAddr)
		}
		nudDisp.expectEvents(t, []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      e.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      e.Addr,
				LinkAddr:  e.LinkAddr,
				State:     Reachable,
			},
		})
	}

	// Use the rest of the entries in the store
	for i := neighborCacheSize; i < store.Len(); i++ {
		e := store.Entry(i)
		got, err := getBlocking(neigh, e, linkRes)
		if err != nil {
			t.Errorf("neigh.entry(%q) got error: %v, want error: %v", e.Addr, err, tcpip.ErrWouldBlock)
		}
		if got.LinkAddr != e.LinkAddr {
			t.Errorf("neigh.entry(%q)=%q, want %q", e.Addr, got.LinkAddr, e.LinkAddr)
		}
		removedEntry := store.Entry(i - neighborCacheSize)
		nudDisp.expectEvents(t, []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Addr:      removedEntry.Addr,
				LinkAddr:  removedEntry.LinkAddr,
				State:     Reachable,
			},
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      e.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      e.Addr,
				LinkAddr:  e.LinkAddr,
				State:     Reachable,
			},
		})
	}

	// Check that after resolved, address stays in the cache and never returns WouldBlock.
	for i := 0; i < neighborCacheSize; i++ {
		e := store.Entry(store.Len() - i - 1)
		got, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil)
		if err != nil {
			t.Errorf("neigh.entry(%q)=%q, got error: %v", e.Addr, got, err)
		}
		if got.LinkAddr != e.LinkAddr {
			t.Errorf("neigh.entry(%q)=%q, want %q", e.Addr, got.LinkAddr, e.LinkAddr)
		}
	}

	nudDisp.expectNoMoreEvents(t)
}

func TestCacheResolutionFailed(t *testing.T) {
	t.Parallel()
	nudDisp := testNUDDispatcher{
		C: make(chan testEntryEventInfo, neighborCacheSize),
	}
	c := DefaultNUDConfigurations()
	c.BaseReachableTime = time.Duration(math.MaxInt64) // approximately 292 years
	c.RetransmitTimer = time.Millisecond
	neigh := newTestNeighborCache(&nudDisp, c)
	store := newTestEntryStore()

	var requestCount uint32
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
		onLinkAddressRequest: func() {
			atomic.AddUint32(&requestCount, 1)
		},
	}

	// First, sanity check that resolution is working
	e := store.Entry(0)
	got, err := getBlocking(neigh, e, linkRes)
	if err != nil {
		t.Errorf("neigh.entry(%q) got error: %v, want error: ErrWouldBlock", e.Addr, err)
	}
	if got.LinkAddr != e.LinkAddr {
		t.Errorf("neigh.entry(%q)=%q, want %q", e.Addr, got.LinkAddr, e.LinkAddr)
	}

	before := atomic.LoadUint32(&requestCount)

	e.Addr += "2"
	if _, err := getBlocking(neigh, e, linkRes); err != tcpip.ErrNoLinkAddress {
		t.Errorf("neigh.entry(%q) got error: %v, want error: ErrNoLinkAddress", e.Addr, err)
	}

	maxAttempts := neigh.config().MaxUnicastProbes
	if got, want := atomic.LoadUint32(&requestCount)-before, maxAttempts; got != want {
		t.Errorf("got link address request count = %d, want = %d", got, want)
	}
}

// TestCacheResolutionTimeout simulates sending MaxMulticastProbes probes and
// not retrieving a confirmation before the duration defined by
// MaxMulticastProbes * RetransmitTimer.
func TestCacheResolutionTimeout(t *testing.T) {
	t.Parallel()
	neigh := newTestNeighborCache(nil, NUDConfigurations{
		BaseReachableTime:  time.Duration(1<<63 - 1), // approximately 290 years
		RetransmitTimer:    time.Millisecond,
		MaxMulticastProbes: 3,
	})
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   time.Second,
	}

	e := store.Entry(0)
	if _, err := getBlocking(neigh, e, linkRes); err != tcpip.ErrNoLinkAddress {
		t.Errorf("neigh.entry(%q) got error: %v, want error: ErrNoLinkAddress", e.Addr, err)
	}
}

// TestStaticResolution checks that static link addresses are resolved
// immediately and don't send resolution requests.
func TestStaticResolution(t *testing.T) {
	t.Parallel()
	neigh := newTestNeighborCache(nil, NUDConfigurations{
		BaseReachableTime:  time.Duration(1<<63 - 1), // approximately 290 years
		RetransmitTimer:    time.Millisecond,
		MaxMulticastProbes: 3,
	})
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   time.Minute,
	}

	addr := tcpip.Address("broadcast")
	localAddr := tcpip.Address("LocalAddr")
	want := tcpip.LinkAddress("mac_broadcast")
	got, _, err := neigh.entry(addr, localAddr, linkRes, nil)
	if err != nil {
		t.Errorf("neigh.entry(%q)=%q, got error: %v", addr, got, err)
	}
	if got.LinkAddr != want {
		t.Errorf("neigh.entry(%q)=%q, want %q", addr, got.LinkAddr, want)
	}
}

func BenchmarkCacheClear(b *testing.B) {
	b.StopTimer()
	nudConfig := DefaultNUDConfigurations()
	neigh := newTestNeighborCache(nil, nudConfig)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		handler: neigh,
		entries: store,
		delay:   0,
	}

	// Clear for every possible size of the cache
	for cacheSize := 0; cacheSize < neighborCacheSize; cacheSize++ {
		// Fill the neighbor cache to capacity.
		for i := 0; i < cacheSize; i++ {
			a := store.Entry(i)
			_, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
			if err != tcpip.ErrWouldBlock {
				panic("expected entry to block")
			}
			if doneCh != nil {
				<-doneCh
			}
		}

		b.StartTimer()
		neigh.clear()
		b.StopTimer()
	}
}
