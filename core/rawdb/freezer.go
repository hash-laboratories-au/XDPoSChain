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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/metrics"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/gofrs/flock"
)

var (
	// errReadOnly is returned if the freezer is opened in read only mode. All the
	// mutations are disallowed.
	errReadOnly = errors.New("read only")

	// errUnknownAncient is returned when the ancient is requested via a name
	// which doesn't have a matching table within the freezer.
	errUnknownAncient = errors.New("unknown ancient")
)

const (
	// freezerRecheckInterval is the frequency to check the key-value database for
	// chain progression that might permit new blocks to be frozen into immutable
	// storage.
	freezerRecheckInterval = time.Minute

	// freezerBatchLimit is the maximum number of blocks to freeze in one batch
	// before doing an fsync and deleting it from the key-value store.
	freezerBatchLimit = 30000
)

// freezer is an memory mapped append-only database to store immutable chain data
// into flat files:
//
//   - The append-only nature ensures that disk writes are minimized.
//   - The memory mapping ensures we can max out system memory for caching without
//     reserving it for go-ethereum. This would also reduce the memory pressure
//     on a system that's actively running garbage collection cycles.
type freezer struct {
	// WARNING: The `frozen` field is accessed atomically. On 32 bit platforms, only
	// 64-bit aligned fields can be atomic. The struct is guaranteed to be so aligned,
	// so take advantage of that. For more information, see:
	// https://golang.org/pkg/sync/atomic/#pkg-note-BUG
	frozen uint64 // Number of blocks already frozen

	tables       map[string]*freezerTable // Data tables for storing everything
	instanceLock *flock.Flock             // File-system lock to prevent double opens
	quit         chan struct{}            // Quit channel to stop the background freezer loop
}

// newFreezer creates a chain freezer that moves ancient chain data into flat
// append-only files for storage savings.
func newFreezer(datadir string, namespace string) (*freezer, error) {
	// Create the initial freezer object
	var (
		readMeter  = metrics.NewRegisteredMeter(namespace+"ancient/read", nil)
		writeMeter = metrics.NewRegisteredMeter(namespace+"ancient/write", nil)
		sizeGauge  = metrics.NewRegisteredCounter(namespace+"ancient/size", nil)
	)
	// Ensure the datadir is not a symbolic link if it exists.
	if info, err := os.Lstat(datadir); !os.IsNotExist(err) {
		if info.Mode()&os.ModeSymlink != 0 {
			log.Warn("Symbolic link ancient database is not supported", "path", datadir)
			return nil, errSymlinkDatadir
		}
	}
	// Leveldb uses LOCK as the filelock filename. To prevent the freezer
	// from naming its lock file LOCK, we use a different name.
	if err := os.MkdirAll(datadir, 0755); err != nil {
		return nil, err
	}
	lock := flock.New(filepath.Join(datadir, "FLOCK"))
	if locked, err := lock.TryLock(); err != nil {
		return nil, err
	} else if !locked {
		return nil, errors.New("locking ancient directory failed (already locked by another process?)")
	}
	// Open all the supported data tables.
	freezer := &freezer{
		instanceLock: lock,
		tables:       make(map[string]*freezerTable),
		quit:         make(chan struct{}),
	}
	for name, disableSnappy := range freezerNoSnappy {
		table, err := newTable(datadir, name, readMeter, writeMeter, sizeGauge, disableSnappy)
		if err != nil {
			for _, table := range freezer.tables {
				table.Close()
			}
			lock.Unlock()
			return nil, err
		}
		freezer.tables[name] = table
	}
	if err := freezer.repair(); err != nil {
		for _, table := range freezer.tables {
			table.Close()
		}
		lock.Unlock()
		return nil, err
	}
	log.Info("Opened ancient database", "database", datadir)
	return freezer, nil
}

// Close terminates the chain freezer, unmapping all the data files.
func (f *freezer) Close() error {
	var errs []error
	close(f.quit)
	for _, table := range f.tables {
		if err := table.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := f.instanceLock.Unlock(); err != nil {
		errs = append(errs, err)
	}
	if errs != nil {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

// HasAncient returns an indicator whether the specified ancient data exists
// in the freezer.
func (f *freezer) HasAncient(kind string, number uint64) (bool, error) {
	if table := f.tables[kind]; table != nil {
		return table.has(number), nil
	}
	return false, nil
}

// Ancient retrieves an ancient binary blob from the append-only immutable files.
func (f *freezer) Ancient(kind string, number uint64) ([]byte, error) {
	if table := f.tables[kind]; table != nil {
		return table.Retrieve(number)
	}
	return nil, errUnknownAncient
}

// Ancients returns the length of the frozen items.
func (f *freezer) Ancients() (uint64, error) {
	return atomic.LoadUint64(&f.frozen), nil
}

// AncientSize returns the ancient size of the specified category.
func (f *freezer) AncientSize(kind string) (uint64, error) {
	if table := f.tables[kind]; table != nil {
		return table.size()
	}
	return 0, errUnknownAncient
}

// AppendAncient injects all binary blobs belong to block at the end of the
// append-only immutable table files.
//
// Notably, this function is lock free but kind of thread-safe. All out-of-order
// injection will be rejected. But if two injections with same number happen at
// the same time, we can get into the trouble.
func (f *freezer) AppendAncient(number uint64, hash, header, body, receipts, td []byte) (err error) {
	// Ensure the binary blobs we are appending is continuous with freezer.
	if atomic.LoadUint64(&f.frozen) != number {
		return errOutOrderInsertion
	}
	// Rollback all inserted data if any operation below fails to keep all tables aligned.
	defer func() {
		if err != nil {
			rerr := f.repair()
			if rerr != nil {
				log.Crit("Failed to repair freezer", "err", rerr)
			}
			log.Info("Append ancient failed", "number", number, "err", err)
		}
	}()
	// Inject all the components into the relevant data tables
	if err := f.tables[freezerHashTable].Append(f.frozen, hash[:]); err != nil {
		log.Error("Failed to append ancient hash", "number", f.frozen, "hash", common.BytesToHash(hash), "err", err)
		return err
	}
	if err := f.tables[freezerHeaderTable].Append(f.frozen, header); err != nil {
		log.Error("Failed to append ancient header", "number", f.frozen, "hash", common.BytesToHash(hash), "err", err)
		return err
	}
	if err := f.tables[freezerBodiesTable].Append(f.frozen, body); err != nil {
		log.Error("Failed to append ancient body", "number", f.frozen, "hash", common.BytesToHash(hash), "err", err)
		return err
	}
	if err := f.tables[freezerReceiptTable].Append(f.frozen, receipts); err != nil {
		log.Error("Failed to append ancient receipts", "number", f.frozen, "hash", common.BytesToHash(hash), "err", err)
		return err
	}
	if err := f.tables[freezerDifficultyTable].Append(f.frozen, td); err != nil {
		log.Error("Failed to append ancient difficulty", "number", f.frozen, "hash", common.BytesToHash(hash), "err", err)
		return err
	}
	atomic.AddUint64(&f.frozen, 1) // Only modify atomically
	return nil
}

// TruncateAncients discards any recent data above the provided threshold number.
func (f *freezer) TruncateAncients(items uint64) error {
	if atomic.LoadUint64(&f.frozen) <= items {
		return nil
	}
	for _, table := range f.tables {
		if err := table.truncate(items); err != nil {
			return err
		}
	}
	atomic.StoreUint64(&f.frozen, items)
	return nil
}

// Sync flushes all data tables to disk.
func (f *freezer) Sync() error {
	var errs []error
	for _, table := range f.tables {
		if err := table.Sync(); err != nil {
			errs = append(errs, err)
		}
	}
	if errs != nil {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

// freeze is a background thread that periodically checks the blockchain for any
// import progress and moves ancient data from the fast database into the freezer.
//
// This functionality is deliberately broken off from block importing to avoid
// incurring additional data shuffling delays on block propagation.
func (f *freezer) freeze(db ethdb.KeyValueStore) {
	nfdb := &nofreezedb{KeyValueStore: db}

	for {
		select {
		case <-f.quit:
			log.Info("Freezer shutting down")
			return
		default:
		}

		// Retrieve the freezing threshold.
		hash := ReadHeadBlockHash(nfdb)
		if hash == (common.Hash{}) {
			log.Debug("Current full block hash unavailable") // new chain, empty database
			time.Sleep(freezerRecheckInterval)
			continue
		}
		number := ReadHeaderNumber(nfdb, hash)
		switch {
		case number == nil:
			log.Error("Current full block number unavailable", "hash", hash)
			time.Sleep(freezerRecheckInterval)
			continue

		case *number < params.ImmutabilityThreshold:
			log.Debug("Current full block not old enough", "number", *number, "hash", hash, "delay", params.ImmutabilityThreshold)
			time.Sleep(freezerRecheckInterval)
			continue

		case *number-params.ImmutabilityThreshold <= f.frozen:
			log.Debug("Ancient blocks frozen already", "number", *number, "hash", hash, "frozen", f.frozen)
			time.Sleep(freezerRecheckInterval)
			continue
		}
		head := ReadHeader(nfdb, hash, *number)
		if head == nil {
			log.Error("Current full block unavailable", "number", *number, "hash", hash)
			time.Sleep(freezerRecheckInterval)
			continue
		}
		// Seems we have data ready to be frozen, process in usable batches
		limit := *number - params.ImmutabilityThreshold
		if limit-f.frozen > freezerBatchLimit {
			limit = f.frozen + freezerBatchLimit
		}
		var (
			start    = time.Now()
			first    = f.frozen
			ancients = make([]common.Hash, 0, limit-f.frozen)
		)
		for f.frozen < limit {
			// Retrieves all the components of the canonical block
			hash := ReadCanonicalHash(nfdb, f.frozen)
			if hash == (common.Hash{}) {
				log.Error("Canonical hash missing, can't freeze", "number", f.frozen)
				break
			}
			header := ReadHeaderRLP(nfdb, hash, f.frozen)
			if len(header) == 0 {
				log.Error("Block header missing, can't freeze", "number", f.frozen, "hash", hash)
				break
			}
			body := ReadBodyRLP(nfdb, hash, f.frozen)
			if len(body) == 0 {
				log.Error("Block body missing, can't freeze", "number", f.frozen, "hash", hash)
				break
			}
			receipts := ReadReceiptsRLP(nfdb, hash, f.frozen)
			if len(receipts) == 0 {
				log.Error("Block receipts missing, can't freeze", "number", f.frozen, "hash", hash)
				break
			}
			td := ReadTdRLP(nfdb, hash, f.frozen)
			if len(td) == 0 {
				log.Error("Total difficulty missing, can't freeze", "number", f.frozen, "hash", hash)
				break
			}
			log.Trace("Deep froze ancient block", "number", f.frozen, "hash", hash)
			if err := f.AppendAncient(f.frozen, hash[:], header, body, receipts, td); err != nil {
				break
			}
			ancients = append(ancients, hash)
		}
		// Batch of blocks have been frozen, flush them before wiping from leveldb
		if err := f.Sync(); err != nil {
			log.Crit("Failed to flush frozen tables", "err", err)
		}
		// Wipe out all data from the active database
		batch := db.NewBatch()
		for i := 0; i < len(ancients); i++ {
			// Always keep the genesis block in active database
			if first+uint64(i) != 0 {
				DeleteBlockWithoutNumber(batch, ancients[i], first+uint64(i))
				DeleteCanonicalHash(batch, first+uint64(i))
			}
		}
		if err := batch.Write(); err != nil {
			log.Crit("Failed to delete frozen canonical blocks", "err", err)
		}
		// Log something friendly for the user
		context := []interface{}{
			"blocks", f.frozen - first, "elapsed", common.PrettyDuration(time.Since(start)), "number", f.frozen - 1,
		}
		if n := len(ancients); n > 0 {
			context = append(context, []interface{}{"hash", ancients[n-1]}...)
		}
		log.Info("Deep froze chain segment", context...)

		// Avoid hammering the database if we are below the threshold or behind
		// by a small amount only
		if limit-first < freezerBatchLimit {
			time.Sleep(freezerRecheckInterval)
		}
	}
}

// repair truncates all data tables to the same length.
func (f *freezer) repair() error {
	min := uint64(0)
	min--
	for _, table := range f.tables {
		items := atomic.LoadUint64(&table.items)
		if min > items {
			min = items
		}
	}
	for _, table := range f.tables {
		if err := table.truncate(min); err != nil {
			return err
		}
	}
	atomic.StoreUint64(&f.frozen, min)
	return nil
}
