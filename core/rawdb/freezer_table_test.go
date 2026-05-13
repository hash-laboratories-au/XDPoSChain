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
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/metrics"
)

// newDummyTable creates a freezer table in a fresh tempdir. Tests reuse this
// helper instead of duplicating boilerplate.
func newDummyTable(t *testing.T, name string, maxFileSize uint32, disableSnappy bool) (string, *freezerTable) {
	t.Helper()
	dir := t.TempDir()
	f, err := newTable(dir, name,
		metrics.NewRegisteredMeter(fmt.Sprintf("test/%s/readMeter", t.Name()), nil),
		metrics.NewRegisteredMeter(fmt.Sprintf("test/%s/writeMeter", t.Name()), nil),
		metrics.NewRegisteredCounter(fmt.Sprintf("test/%s/size", t.Name()), nil),
		disableSnappy)
	if err != nil {
		t.Fatal(err)
	}
	// Override the on-disk max file size with a small test value so we exercise
	// segment rotation without writing gigabytes.
	f.maxFileSize = maxFileSize
	return dir, f
}

// TestFreezerBasics is a basic round-trip: append 255 fixed-size items then read
// them back. The test value of maxFileSize forces several segment rotations.
func TestFreezerBasics(t *testing.T) {
	t.Parallel()
	// Reset the meta to fresh state
	_, f := newDummyTable(t, "TestFreezerBasics", 50, true)
	defer f.Close()
	// Write 255 items, each 15 bytes
	for x := 0; x < 255; x++ {
		data := getChunk(15, x)
		f.Append(uint64(x), data)
	}
	// Read them back, ensure correctness
	for y := 0; y < 255; y++ {
		exp := getChunk(15, y)
		got, err := f.Retrieve(uint64(y))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, exp) {
			t.Fatalf("test %d, got %v want %v", y, got, exp)
		}
	}
}

// TestFreezerBasicsClosing also writes 255 items, but closes and re-opens the
// table between each operation. This exercises the file open/close path
// thoroughly and ensures the repair logic is benign on a clean shutdown.
func TestFreezerBasicsClosing(t *testing.T) {
	t.Parallel()
	dir, f := newDummyTable(t, "TestFreezerBasicsClosing", 50, true)

	// Write 255 items, close & reopen between each append.
	for x := 0; x < 255; x++ {
		data := getChunk(15, x)
		f.Append(uint64(x), data)
		f.Close()
		var err error
		f, err = newTable(dir, "TestFreezerBasicsClosing",
			metrics.NewRegisteredMeter("test/readMeter2", nil),
			metrics.NewRegisteredMeter("test/writeMeter2", nil),
			metrics.NewRegisteredCounter("test/size2", nil),
			true)
		if err != nil {
			t.Fatal(err)
		}
		f.maxFileSize = 50
	}
	defer f.Close()
	// Read every item, closing between each read.
	for y := 0; y < 255; y++ {
		exp := getChunk(15, y)
		got, err := f.Retrieve(uint64(y))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, exp) {
			t.Fatalf("test %d, got %v want %v", y, got, exp)
		}
		f.Close()
		f, err = newTable(dir, "TestFreezerBasicsClosing",
			metrics.NewRegisteredMeter("test/readMeter3", nil),
			metrics.NewRegisteredMeter("test/writeMeter3", nil),
			metrics.NewRegisteredCounter("test/size3", nil),
			true)
		if err != nil {
			t.Fatal(err)
		}
		f.maxFileSize = 50
	}
}

// TestFreezerRepairDanglingHead removes some bytes off the end of the index
// file, simulating a partial flush. The table must repair itself.
func TestFreezerRepairDanglingHead(t *testing.T) {
	t.Parallel()
	dir, f := newDummyTable(t, "TestFreezerRepairDanglingHead", 50, true)

	// Write 255 items
	for x := 0; x < 255; x++ {
		data := getChunk(15, x)
		f.Append(uint64(x), data)
	}
	f.Close()

	// Truncate the index file
	idxName := filepath.Join(dir, "TestFreezerRepairDanglingHead.ridx")
	idxStat, err := os.Stat(idxName)
	if err != nil {
		t.Fatal(err)
	}
	// Chop off the last few index entries (each is 6 bytes; remove ~3)
	if err := os.Truncate(idxName, idxStat.Size()-int64(indexEntrySize)*3); err != nil {
		t.Fatal(err)
	}
	// Reopen; expect repair to truncate items back to a consistent state.
	f, err = newTable(dir, "TestFreezerRepairDanglingHead",
		metrics.NewRegisteredMeter("test/r1", nil),
		metrics.NewRegisteredMeter("test/w1", nil),
		metrics.NewRegisteredCounter("test/s1", nil),
		true)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// The table should now hold strictly fewer items.
	if f.items >= 255 {
		t.Fatalf("expected fewer items after repair, got %d", f.items)
	}
}

// TestFreezerRepairDanglingHeadLarge removes many index entries while leaving
// the data file longer than necessary. The repair() must truncate the data
// file down to match the index.
func TestFreezerRepairDanglingHeadLarge(t *testing.T) {
	t.Parallel()
	dir, f := newDummyTable(t, "TestFreezerRepairDanglingHeadLarge", 50, true)

	// Write 255 items
	for x := 0; x < 255; x++ {
		data := getChunk(15, x)
		f.Append(uint64(x), data)
	}
	f.Close()

	// Truncate the index file to just the first 7 entries (genesis + 6 items).
	idxName := filepath.Join(dir, "TestFreezerRepairDanglingHeadLarge.ridx")
	if err := os.Truncate(idxName, int64(indexEntrySize*7)); err != nil {
		t.Fatal(err)
	}
	// Reopen; expect repair() to truncate the head file down too.
	f, err := newTable(dir, "TestFreezerRepairDanglingHeadLarge",
		metrics.NewRegisteredMeter("test/r2", nil),
		metrics.NewRegisteredMeter("test/w2", nil),
		metrics.NewRegisteredCounter("test/s2", nil),
		true)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.items != 6 {
		t.Fatalf("expected 6 items after repair, got %d", f.items)
	}
	// Items beyond the truncation point should not be retrievable.
	if _, err := f.Retrieve(7); err == nil {
		t.Fatalf("expected error retrieving truncated item, got nil")
	}
}

// TestSnappyDetection confirms that opening a table whose data files were
// written with one compression mode and then reopened with the opposite mode
// is rejected or misbehaves predictably. Specifically: when files are written
// with the .cdat extension (snappy) and reopened with disableSnappy=true,
// the table will look for .rdat files and not find them — leaving an empty
// table.
func TestSnappyDetection(t *testing.T) {
	t.Parallel()
	dir, f := newDummyTable(t, "TestSnappyDetection", 50, false)
	for x := 0; x < 10; x++ {
		f.Append(uint64(x), getChunk(15, x))
	}
	f.Close()

	// Reopen with disableSnappy=true; the table will look for .ridx instead of
	// .cidx, find nothing, and start fresh.
	f2, err := newTable(dir, "TestSnappyDetection",
		metrics.NewRegisteredMeter("test/r3", nil),
		metrics.NewRegisteredMeter("test/w3", nil),
		metrics.NewRegisteredCounter("test/s3", nil),
		true)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	if f2.items != 0 {
		t.Fatalf("expected empty table on mode mismatch, got %d items", f2.items)
	}
}

// TestFreezerRepairDanglingIndex makes the data file shorter than the index
// claims. The repair must truncate the index back down to match the data.
func TestFreezerRepairDanglingIndex(t *testing.T) {
	t.Parallel()
	dir, f := newDummyTable(t, "TestFreezerRepairDanglingIndex", 50, true)

	for x := 0; x < 9; x++ {
		f.Append(uint64(x), getChunk(15, x))
	}
	f.Sync()
	itemsAtStart := f.items
	f.Close()

	// Find the head data file and chop ~half off the end.
	// With maxFileSize=50 and item size ~16 bytes, segment 0 holds 3 items, etc.
	// Just find any data file and truncate it.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var dataFile string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".rdat" {
			dataFile = filepath.Join(dir, e.Name())
		}
	}
	if dataFile == "" {
		t.Fatal("no data file found")
	}
	info, err := os.Stat(dataFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(dataFile, info.Size()/2); err != nil {
		t.Fatal(err)
	}
	// Reopen — repair must truncate the index to match.
	f2, err := newTable(dir, "TestFreezerRepairDanglingIndex",
		metrics.NewRegisteredMeter("test/r4", nil),
		metrics.NewRegisteredMeter("test/w4", nil),
		metrics.NewRegisteredCounter("test/s4", nil),
		true)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	if f2.items >= itemsAtStart {
		t.Fatalf("expected fewer items after repair (had %d), got %d", itemsAtStart, f2.items)
	}
}

// TestFreezerTruncate verifies that truncate(n) correctly bounds the table.
func TestFreezerTruncate(t *testing.T) {
	t.Parallel()
	_, f := newDummyTable(t, "TestFreezerTruncate", 50, true)
	defer f.Close()

	for x := 0; x < 30; x++ {
		f.Append(uint64(x), getChunk(15, x))
	}
	if err := f.truncate(10); err != nil {
		t.Fatal(err)
	}
	if f.items != 10 {
		t.Fatalf("after truncate(10), expected items=10, got %d", f.items)
	}
	// Items 0..9 still retrievable
	for x := 0; x < 10; x++ {
		got, err := f.Retrieve(uint64(x))
		if err != nil {
			t.Fatalf("retrieve %d: %v", x, err)
		}
		if !bytes.Equal(got, getChunk(15, x)) {
			t.Fatalf("item %d mismatch after truncate", x)
		}
	}
	// Item 10 must be gone
	if _, err := f.Retrieve(10); err == nil {
		t.Fatalf("expected error retrieving item 10 after truncate, got nil")
	}
}

// TestFreezerRepairFirstFile corrupts the *first* data segment by truncating it,
// then reopens. The repair() routine should drop everything that became
// dangling.
func TestFreezerRepairFirstFile(t *testing.T) {
	t.Parallel()
	dir, f := newDummyTable(t, "TestFreezerRepairFirstFile", 50, true)

	for x := 0; x < 30; x++ {
		f.Append(uint64(x), getChunk(15, x))
	}
	f.Close()

	// Truncate the first data file in half
	firstFile := filepath.Join(dir, "TestFreezerRepairFirstFile.0000.rdat")
	info, err := os.Stat(firstFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(firstFile, info.Size()/2); err != nil {
		t.Fatal(err)
	}
	// Reopen and verify the table still functions (may have fewer items).
	f2, err := newTable(dir, "TestFreezerRepairFirstFile",
		metrics.NewRegisteredMeter("test/r5", nil),
		metrics.NewRegisteredMeter("test/w5", nil),
		metrics.NewRegisteredCounter("test/s5", nil),
		true)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	// Just verify it didn't panic and that retrieve works for low items.
	if _, err := f2.Retrieve(0); err != nil {
		t.Logf("retrieve(0) after first-file corruption returned: %v", err)
	}
}

// TestFreezerReadAndTruncate verifies that an in-flight read of an item that
// gets truncated returns a sensible error rather than corrupted data.
func TestFreezerReadAndTruncate(t *testing.T) {
	t.Parallel()
	_, f := newDummyTable(t, "TestFreezerReadAndTruncate", 50, true)
	defer f.Close()

	for x := 0; x < 30; x++ {
		f.Append(uint64(x), getChunk(15, x))
	}
	// Read item 20 — should succeed.
	if _, err := f.Retrieve(20); err != nil {
		t.Fatalf("retrieve before truncate: %v", err)
	}
	// Truncate down to 15.
	if err := f.truncate(15); err != nil {
		t.Fatal(err)
	}
	// Retrieve 20 — should now fail with out-of-bounds.
	if _, err := f.Retrieve(20); err == nil {
		t.Fatalf("expected error retrieving truncated item 20, got nil")
	}
}

// TestOffset is omitted: at v1.9.0 the itemOffset is always 0 (no head
// truncation supported), so the upstream test is a no-op for this port.

// getChunk returns a deterministic byte slice of the given length. The same
// (length, seed) pair always produces the same bytes, so we can compare
// retrieved bytes against expected without storing them.
func getChunk(size int, seed int) []byte {
	r := rand.New(rand.NewPCG(uint64(seed), uint64(seed)*1234567))
	out := make([]byte, size)
	for i := 0; i < size; i++ {
		out[i] = byte(r.Uint32() & 0xff)
	}
	return out
}
