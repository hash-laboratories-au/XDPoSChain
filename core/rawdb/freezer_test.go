// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package rawdb

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/ethdb/memorydb"
)

// makeBlobs returns deterministic per-block placeholder blobs for the five
// freezer tables.
func makeBlobs(seed byte) (hash, header, body, receipts, td []byte) {
	hash = bytes.Repeat([]byte{seed}, 32)
	header = []byte(fmt.Sprintf("header-%d", seed))
	body = []byte(fmt.Sprintf("body-%d", seed))
	receipts = []byte(fmt.Sprintf("receipts-%d", seed))
	td = []byte(fmt.Sprintf("td-%d", seed))
	return
}

// TestFreezerAppendAndRead exercises AppendAncient / Ancient / HasAncient /
// Ancients / AncientSize against a real freezer in a temp directory.
func TestFreezerAppendAndRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f, err := newFreezer(dir, "test/")
	if err != nil {
		t.Fatalf("newFreezer: %v", err)
	}
	defer f.Close()

	// Append five blocks.
	const n = 5
	for i := uint64(0); i < n; i++ {
		hash, header, body, receipts, td := makeBlobs(byte(i + 1))
		if err := f.AppendAncient(i, hash, header, body, receipts, td); err != nil {
			t.Fatalf("AppendAncient(%d): %v", i, err)
		}
	}
	// Ancients() returns the count.
	if got, _ := f.Ancients(); got != n {
		t.Fatalf("Ancients() = %d, want %d", got, n)
	}
	// HasAncient / Ancient for each kind.
	for i := uint64(0); i < n; i++ {
		ok, err := f.HasAncient(freezerHashTable, i)
		if err != nil || !ok {
			t.Fatalf("HasAncient(hash,%d) = (%v,%v)", i, ok, err)
		}
		expHash, expHeader, expBody, expReceipts, expTd := makeBlobs(byte(i + 1))
		check := func(kind string, want []byte) {
			got, err := f.Ancient(kind, i)
			if err != nil {
				t.Fatalf("Ancient(%s, %d): %v", kind, i, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Ancient(%s, %d) = %x, want %x", kind, i, got, want)
			}
		}
		check(freezerHashTable, expHash)
		check(freezerHeaderTable, expHeader)
		check(freezerBodiesTable, expBody)
		check(freezerReceiptTable, expReceipts)
		check(freezerDifficultyTable, expTd)
	}
	// AncientSize is non-zero for each kind.
	for _, kind := range []string{freezerHashTable, freezerHeaderTable, freezerBodiesTable, freezerReceiptTable, freezerDifficultyTable} {
		sz, err := f.AncientSize(kind)
		if err != nil {
			t.Fatalf("AncientSize(%s): %v", kind, err)
		}
		if sz == 0 {
			t.Fatalf("AncientSize(%s) = 0, expected > 0", kind)
		}
	}
}

// TestFreezerOutOfOrderAppend ensures AppendAncient rejects non-sequential
// inserts.
func TestFreezerOutOfOrderAppend(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f, err := newFreezer(dir, "test/")
	if err != nil {
		t.Fatalf("newFreezer: %v", err)
	}
	defer f.Close()

	hash, header, body, receipts, td := makeBlobs(1)
	// First-ever append, but with number=5 instead of 0 — must fail.
	err = f.AppendAncient(5, hash, header, body, receipts, td)
	if err == nil {
		t.Fatalf("expected AppendAncient(5) on empty freezer to fail, got nil")
	}
	if !errors.Is(err, errOutOrderInsertion) {
		t.Fatalf("expected errOutOrderInsertion, got %v", err)
	}
}

// TestFreezerTruncateAncients verifies TruncateAncients trims all five tables
// to the same length and updates the atomic counter.
func TestFreezerTruncateAncients(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f, err := newFreezer(dir, "test/")
	if err != nil {
		t.Fatalf("newFreezer: %v", err)
	}
	defer f.Close()

	// Append 10 blocks then truncate to 4.
	for i := uint64(0); i < 10; i++ {
		hash, header, body, receipts, td := makeBlobs(byte(i + 1))
		if err := f.AppendAncient(i, hash, header, body, receipts, td); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.TruncateAncients(4); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.Ancients(); got != 4 {
		t.Fatalf("after TruncateAncients(4), Ancients()=%d, want 4", got)
	}
	// Item 3 still readable, item 4 not.
	if _, err := f.Ancient(freezerHashTable, 3); err != nil {
		t.Fatalf("Ancient(hash, 3) after truncate: %v", err)
	}
	if _, err := f.Ancient(freezerHashTable, 4); err == nil {
		t.Fatalf("expected Ancient(hash, 4) to fail after truncate, got nil")
	}
}

// TestFreezerLockExclusive verifies that two freezer instances on the same
// directory cannot coexist.
func TestFreezerLockExclusive(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first, err := newFreezer(dir, "test/")
	if err != nil {
		t.Fatalf("first newFreezer: %v", err)
	}
	defer first.Close()

	if _, err := newFreezer(dir, "test/"); err == nil {
		t.Fatalf("expected second newFreezer on same dir to fail, got nil")
	}
}

// TestNewDatabaseWithFreezer_GenesisMismatch verifies the sanity check that
// blocks combining a leveldb whose genesis disagrees with the ancient store.
func TestNewDatabaseWithFreezer_GenesisMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Pre-seed an ancient store with genesis hash 0xAA...
	f, err := newFreezer(dir, "test/")
	if err != nil {
		t.Fatal(err)
	}
	hash, header, body, receipts, td := makeBlobs(0xAA)
	if err := f.AppendAncient(0, hash, header, body, receipts, td); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Now make a kv store whose genesis is 0xBB... and try to combine.
	kv := memorydb.New()
	conflicting := bytes.Repeat([]byte{0xBB}, 32)
	if err := kv.Put(headerHashKey(0), conflicting); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDatabaseWithFreezer(kv, dir, "test2/"); err == nil {
		t.Fatalf("expected NewDatabaseWithFreezer to reject genesis mismatch, got nil")
	}
}
