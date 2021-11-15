package engine_v2

import (
	"bytes"
	"encoding/json"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
	lru "github.com/hashicorp/golang-lru"
)

// Snapshot is the state of the authorization voting at a given point in time.
type SnapshotV2 struct {
	config   *params.XDPoSConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache       // Cache of recent block signatures to speed up ecrecover

	Number     uint64           `json:"number"`     // Block number where the snapshot was created
	Hash       common.Hash      `json:"hash"`       // Block hash where the snapshot was created
	EpochRound utils.Round      `json:"epochRound"` // Block BTF Epoch start round
	QuorumCert utils.QuorumCert `json:"quorumCert"` // Block's QC

	MasterNodes map[common.Address]struct{} `json:"masterNodes"` // Set of authorized master nodes at this moment
	Recents     map[uint64]common.Address   `json:"recents"`     // Set of recent signers for spam protections
}

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent signers, so only ever use if for
// the genesis block.
func newSnapshot(config *params.XDPoSConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, round utils.Round, qc utils.QuorumCert, signers []common.Address) *SnapshotV2 {
	snap := &SnapshotV2{
		config:     config,
		sigcache:   sigcache,
		Number:     number,
		Hash:       hash,
		EpochRound: round,
		QuorumCert: qc,

		MasterNodes: make(map[common.Address]struct{}),
		Recents:     make(map[uint64]common.Address),
	}
	for _, signer := range signers {
		snap.MasterNodes[signer] = struct{}{}
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.XDPoSConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*SnapshotV2, error) {
	blob, err := db.Get(append([]byte("XDPoS-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(SnapshotV2)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the SnapshotV2 into the database.
func (s *SnapshotV2) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("XDPoS-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the SnapshotV2, though not the individual votes.
func (s *SnapshotV2) copy() *SnapshotV2 {
	cpy := &SnapshotV2{
		config:      s.config,
		sigcache:    s.sigcache,
		Number:      s.Number,
		Hash:        s.Hash,
		MasterNodes: make(map[common.Address]struct{}),
		Recents:     make(map[uint64]common.Address),
	}
	for signer := range s.MasterNodes {
		cpy.MasterNodes[signer] = struct{}{}
	}
	for block, signer := range s.Recents {
		cpy.Recents[block] = signer
	}

	return cpy
}

// apply creates a new authorization SnapshotV2 by applying the given headers to
// the original one.
func (s *SnapshotV2) apply(headers []*types.Header) (*SnapshotV2, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, utils.ErrInvalidVotingChain
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, utils.ErrInvalidVotingChain
	}
	// Iterate through the headers and create a new SnapshotV2
	snap := s.copy()

	for _, header := range headers {
		// Remove any votes on checkpoint blocks
		number := header.Number.Uint64()
		// Delete the oldest signer from the recent list to allow it signing again
		if limit := uint64(len(snap.MasterNodes)/2 + 1); number >= limit {
			delete(snap.Recents, number-limit)
		}
		// Resolve the authorization key and check against signers
		signer, err := utils.Ecrecover(header, s.sigcache)
		if err != nil {
			return nil, err
		}
		snap.Recents[number] = signer
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()
	// TODO snap.QuorumCert = headers[len(headers)-1].QC()
	// TODO snap.EpochRound = getEpochRound(header)
	return snap, nil
}

// signers retrieves the list of authorized signers in ascending order.
func (s *SnapshotV2) GetMasterNodes() []common.Address {
	signers := make([]common.Address, 0, len(s.MasterNodes))
	for signer := range s.MasterNodes {
		signers = append(signers, signer)
	}
	for i := 0; i < len(signers); i++ {
		for j := i + 1; j < len(signers); j++ {
			if bytes.Compare(signers[i][:], signers[j][:]) > 0 {
				signers[i], signers[j] = signers[j], signers[i]
			}
		}
	}
	return signers
}
