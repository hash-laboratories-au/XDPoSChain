// WIP XDPoS 2.0
package XDPoS

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// XDPoS is the proof-of-stake-voting consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type EngineV2 struct {
}

func SigHashV2(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()

	rlp.Encode(hasher, []interface{}{})
	hasher.Sum(hash[:0])
	return hash
}

// New creates a XDPoS proof-of-stake-voting consensus engine with the initial
// signers set to the ones provided by the user.
func NewV2Engine() *EngineV2 {
	return &EngineV2{}
}

func (c *EngineV2) Author(header *types.Header) (common.Address, error) {
	var signer common.Address
	return signer, nil
}
