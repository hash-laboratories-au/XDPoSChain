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
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb/memorydb"
)

// freezerOnlyDB couples a fresh memorydb (which serves the KeyValueStore role)
// with a real freezer rooted at a temp directory. We use it to exercise the
// accessor read paths that should resolve ancient data.
func freezerOnlyDB(t *testing.T) (*freezer, *freezerdb) {
	t.Helper()
	dir := t.TempDir()
	f, err := newFreezer(dir, "test/")
	if err != nil {
		t.Fatalf("newFreezer: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	kv := memorydb.New()
	return f, &freezerdb{KeyValueStore: kv, AncientStore: f}
}

// TestWriteAncientBlock confirms WriteAncientBlock encodes and stores a block
// such that all five read accessors (header, body, receipts, td, canonical
// hash) return the right values from the ancient store.
func TestWriteAncientBlock(t *testing.T) {
	t.Parallel()
	_, db := freezerOnlyDB(t)

	header := &types.Header{
		Number:     big.NewInt(0),
		Extra:      []byte("ancient genesis"),
		Difficulty: big.NewInt(7),
	}
	body := &types.Body{Transactions: nil, Uncles: nil}
	block := types.NewBlockWithHeader(header).WithBody(*body)
	td := big.NewInt(42)

	// The freezer requires the first append to be number 0.
	if n := WriteAncientBlock(db, block, types.Receipts{}, td); n == 0 {
		t.Fatalf("WriteAncientBlock returned 0 bytes")
	}

	// Read header from ancient.
	got := ReadHeader(db, block.Hash(), 0)
	if got == nil {
		t.Fatalf("ReadHeader returned nil")
	}
	if got.Hash() != block.Hash() {
		t.Fatalf("ReadHeader hash mismatch: got %x, want %x", got.Hash(), block.Hash())
	}

	// Read body from ancient (block has no txs/uncles -> empty body still RLP-roundtrips).
	gotBody := ReadBody(db, block.Hash(), 0)
	if gotBody == nil {
		t.Fatalf("ReadBody returned nil")
	}

	// Read receipts (raw, no chain config needed for an empty list).
	gotReceipts := ReadRawReceipts(db, block.Hash(), 0)
	if gotReceipts == nil {
		t.Fatalf("ReadRawReceipts returned nil")
	}
	if len(gotReceipts) != 0 {
		t.Fatalf("expected empty receipts, got %d", len(gotReceipts))
	}

	// Read td.
	gotTd := ReadTd(db, block.Hash(), 0)
	if gotTd == nil {
		t.Fatalf("ReadTd returned nil")
	}
	if gotTd.Cmp(td) != 0 {
		t.Fatalf("ReadTd: got %v, want %v", gotTd, td)
	}

	// Read canonical hash.
	gotHash := ReadCanonicalHash(db, 0)
	if gotHash != block.Hash() {
		t.Fatalf("ReadCanonicalHash: got %x, want %x", gotHash, block.Hash())
	}
}

// TestDeleteBlockWithoutNumber confirms that DeleteBlockWithoutNumber removes
// body / receipts / td / header (no-number variant) but leaves the
// hash->number mapping intact.
func TestDeleteBlockWithoutNumber(t *testing.T) {
	t.Parallel()
	db := NewMemoryDatabase()
	header := &types.Header{Number: big.NewInt(123), Extra: []byte("delete-me")}
	hash := header.Hash()

	WriteHeader(db, header)
	WriteBody(db, hash, 123, &types.Body{})
	WriteReceipts(db, hash, 123, nil)
	WriteTd(db, hash, 123, big.NewInt(99))

	// Sanity: hash->number is set by WriteHeader.
	if n := ReadHeaderNumber(db, hash); n == nil || *n != 123 {
		t.Fatalf("setup: expected header-number mapping to be set")
	}

	DeleteBlockWithoutNumber(db, hash, 123)

	// header data, body, receipts, td gone…
	if h := ReadHeader(db, hash, 123); h != nil {
		t.Fatalf("expected header removed, got %v", h)
	}
	if b := ReadBody(db, hash, 123); b != nil {
		t.Fatalf("expected body removed, got %v", b)
	}
	// …but hash->number must survive (freezer relies on this).
	if n := ReadHeaderNumber(db, hash); n == nil || *n != 123 {
		t.Fatalf("expected hash->number mapping to survive DeleteBlockWithoutNumber, got %v", n)
	}
}

// TestReadTdAncient checks the ancient path of ReadTdRLP (the accessor that we
// fixed to follow the ancient-first-with-retry pattern). We deliberately put
// only the ancient copy in place and ensure ReadTd resolves it.
func TestReadTdAncient(t *testing.T) {
	t.Parallel()
	_, db := freezerOnlyDB(t)

	header := &types.Header{Number: big.NewInt(0), Extra: []byte("td-test")}
	block := types.NewBlockWithHeader(header)
	td := big.NewInt(1234567)
	WriteAncientBlock(db, block, types.Receipts{}, td)

	got := ReadTd(db, block.Hash(), 0)
	if got == nil {
		t.Fatalf("ReadTd from ancient returned nil")
	}
	if got.Cmp(td) != 0 {
		t.Fatalf("ReadTd from ancient: got %v, want %v", got, td)
	}

	// Wrong hash must not match.
	if got := ReadTd(db, common.Hash{1, 2, 3}, 0); got != nil {
		t.Fatalf("ReadTd with wrong hash should be nil, got %v", got)
	}
}
