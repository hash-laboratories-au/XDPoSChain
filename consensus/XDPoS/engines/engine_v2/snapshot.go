package engine_v2

import (
	"encoding/json"
	"sort"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
	lru "github.com/hashicorp/golang-lru"
)

// Snapshot is the state of the smart contract validator list
type SnapshotV2 struct {
	config   *params.XDPoSConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache       // Cache of recent block signatures to speed up ecrecover

	Number uint64      `json:"number"` // Block number where the snapshot was created
	Hash   common.Hash `json:"hash"`   // Block hash where the snapshot was created

	MasterNodes map[common.Address]struct{} `json:"masterNodes"` // Set of authorized master nodes at this moment
}

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent signers, so only ever use if for
// the genesis block.
func newSnapshot(config *params.XDPoSConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, round utils.Round, qc *utils.QuorumCert, signers []common.Address) *SnapshotV2 {
	snap := &SnapshotV2{
		config:   config,
		sigcache: sigcache,
		Number:   number,
		Hash:     hash,

		MasterNodes: make(map[common.Address]struct{}),
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
func storeSnapshot(s *SnapshotV2, db ethdb.Database) error {
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
	}
	for signer := range s.MasterNodes {
		cpy.MasterNodes[signer] = struct{}{}
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

	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()
	return snap, nil
}

// signers retrieves the list of authorized signers in ascending order, convert into strings then use native sort lib
func (s *SnapshotV2) GetMasterNodes() []common.Address {
	signers := make([]common.Address, 0, len(s.MasterNodes))
	signerStrs := make([]string, 0, len(s.MasterNodes))

	for signer := range s.MasterNodes {
		signerStrs = append(signerStrs, signer.Str())
	}
	sort.Strings(signerStrs)
	for _, str := range signerStrs {
		signers = append(signers, common.StringToAddress(str))
	}

	return signers
}
