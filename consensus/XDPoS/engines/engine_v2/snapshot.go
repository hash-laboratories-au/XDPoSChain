package engine_v2

import (
	"encoding/json"
	"sort"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	lru "github.com/hashicorp/golang-lru"
)

// Snapshot is the state of the smart contract validator list
type SnapshotV2 struct {
	Round  utils.Round `json:"round"`  // Round number
	Number uint64      `json:"number"` // Block number where the snapshot was created
	Hash   common.Hash `json:"hash"`   // Block hash where the snapshot was created

	// MasterNodes will get assigned on updateM1
	NextEpochMasterNodes map[common.Address]struct{} `json:"masterNodes"` // Set of authorized master nodes at this moment for next epoch
}

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent signers, so only ever use if for
// the genesis block.
func newSnapshot(number uint64, hash common.Hash, round utils.Round, qc *utils.QuorumCert, masternodes map[common.Address]struct{}) *SnapshotV2 {
	snap := &SnapshotV2{
		Round:                round,
		Number:               number,
		Hash:                 hash,
		NextEpochMasterNodes: masternodes,
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*SnapshotV2, error) {
	blob, err := db.Get(append([]byte("XDPoS-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(SnapshotV2)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}

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

// signers retrieves the list of authorized signers in ascending order, convert into strings then use native sort lib
func (s *SnapshotV2) GetMasterNodes() []common.Address {
	nodes := make([]common.Address, 0, len(s.NextEpochMasterNodes))
	nodeStrs := make([]string, 0, len(s.NextEpochMasterNodes))

	for node := range s.NextEpochMasterNodes {
		nodeStrs = append(nodeStrs, node.Str())
	}
	sort.Strings(nodeStrs)
	for _, str := range nodeStrs {
		nodes = append(nodes, common.StringToAddress(str))
	}

	return nodes
}
