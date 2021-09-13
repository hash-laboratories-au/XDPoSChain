// Engine adaptor acting as the wrapper on top of existing engines. It's used to support multiple consensus engine
package XDPoS

import (
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
)

// SignerFn is a signer callback function to request a hash to be signed by a
// backing account.
//type SignerFn func(accounts.Account, []byte) ([]byte, error)

// sigHash returns the hash which is used as input for the proof-of-stake-voting
// signing. It is the hash of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func SigHash(header *types.Header) (hash common.Hash) {
	switch params.BlockConsensusVersion(header.Number) {
	case "2.0":
		return SigHashV2(header)
	default: // Default "1.0"
		return SigHashV1(header)
	}
}

// XDPoS is the proof-of-stake-voting consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type EngineAdaptor struct {
	config *params.XDPoSConfig // Consensus engine configuration parameters
	db     ethdb.Database      // Database to store and retrieve snapshot checkpoints

	signer common.Address  // Ethereum address of the signing key
	signFn clique.SignerFn // Signer function to authorize hashes with
	lock   sync.RWMutex    // Protects the signer fields

	Engine_v1 EngineV1
	Engine_v2 EngineV2
}

// New creates a XDPoS proof-of-stake-voting consensus engine with the initial
// signers set to the ones provided by the user.
func New(config *params.XDPoSConfig, db ethdb.Database) *EngineAdaptor {
	// Set any missing consensus parameters to their defaults
	conf := *config
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}
	return &EngineAdaptor{
		config: &conf,
		db:     db,

		Engine_v1: *NewV1Engine(&conf),
		Engine_v2: *NewV2Engine(),
	}
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (adaptor *EngineAdaptor) Author(header *types.Header) (common.Address, error) {
	switch params.BlockConsensusVersion(header.Number) {
	case "2.0":
		return adaptor.Engine_v2.Author(header)
	default: // Default "1.0"
		return adaptor.Engine_v1.Author(header)
	}
}

// // VerifyHeader checks whether a header conforms to the consensus rules.
func (adaptor *EngineAdaptor) VerifyHeader(chain consensus.ChainReader, header *types.Header, fullVerify bool) error {
	return adaptor.Engine_v1.VerifyHeader(chain, header, fullVerify, adaptor.db)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (adaptor *EngineAdaptor) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, fullVerifies []bool) (chan<- struct{}, <-chan error) {
	return adaptor.Engine_v1.VerifyHeaders(chain, headers, fullVerifies, adaptor.db)
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (adaptor *EngineAdaptor) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	return adaptor.Engine_v1.VerifyUncles(chain, block)
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (adaptor *EngineAdaptor) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return adaptor.Engine_v1.VerifySeal(chain, header, adaptor.db)
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (adaptor *EngineAdaptor) Prepare(chain consensus.ChainReader, header *types.Header) error {
	return adaptor.Engine_v1.Prepare(chain, header, adaptor.signer, adaptor.db)
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (adaptor *EngineAdaptor) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	return adaptor.Engine_v1.Finalize(chain, header, state, txs, uncles, receipts)
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (adaptor *EngineAdaptor) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	return adaptor.Engine_v1.Seal(chain, block, results, stop, adaptor.signer, adaptor.signFn, adaptor.db)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (adaptor *EngineAdaptor) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return adaptor.Engine_v1.CalcDifficulty(chain, time, parent, adaptor.signer, adaptor.db)
}

// SealHash returns the hash of a block prior to it being sealed.
func (adaptor *EngineAdaptor) SealHash(header *types.Header) common.Hash {
	return adaptor.Engine_v1.SealHash(header)
}

// Close implements consensus.Engine. It's a noop for XDPoS as there are no background threads.
func (adaptor *EngineAdaptor) Close() error {
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (adaptor *EngineAdaptor) APIs(chain consensus.ChainReader) []rpc.API {
	// To be upgraded to 2.0 and backwards compatible with 1.0
	return []rpc.API{{
		Namespace: "XDPoS",
		Version:   "1.0",
		Service:   NewAPI(chain, adaptor),
		Public:    false,
	}}
}

// ----------------------------Shared----------

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (adaptor *EngineAdaptor) Authorize(signer common.Address, signFn clique.SignerFn) {
	adaptor.lock.Lock()
	defer adaptor.lock.Unlock()

	adaptor.signer = signer
	adaptor.signFn = signFn
}

func (adaptor *EngineAdaptor) GetDb() ethdb.Database {
	return adaptor.db
}

// -----------------------------XDC specific------------------------------------
func (adaptor *EngineAdaptor) GetSnapshot(chain consensus.ChainReader, header *types.Header) (*Snapshot, error) {
	return adaptor.Engine_v1.GetSnapshot(chain, header, adaptor.db)
}

func (adaptor *EngineAdaptor) GetMasternodes(chain consensus.ChainReader, header *types.Header) []common.Address {
	return adaptor.Engine_v1.GetMasternodes(chain, header)
}

func (adaptor *EngineAdaptor) YourTurn(chain consensus.ChainReader, parent *types.Header, signer common.Address) (int, int, int, bool, error) {
	return adaptor.Engine_v1.YourTurn(chain, parent, signer, adaptor.signer, adaptor.db)
}

func (adaptor *EngineAdaptor) GetValidator(creator common.Address, chain consensus.ChainReader, header *types.Header) (common.Address, error) {
	return adaptor.Engine_v1.GetValidator(creator, chain, header)
}

func (adaptor *EngineAdaptor) UpdateMasternodes(chain consensus.ChainReader, header *types.Header, ms []Masternode) error {
	return adaptor.Engine_v1.UpdateMasternodes(chain, header, ms, adaptor.db)
}

func (adaptor *EngineAdaptor) CacheData(header *types.Header, txs []*types.Transaction, receipts []*types.Receipt) []*types.Transaction {
	return adaptor.Engine_v1.CacheData(header, txs, receipts)
}

func (adaptor *EngineAdaptor) CacheSigner(hash common.Hash, txs []*types.Transaction) []*types.Transaction {
	return adaptor.Engine_v1.CacheSigner(hash, txs)
}

func (adaptor *EngineAdaptor) RecoverSigner(header *types.Header) (common.Address, error) {
	return adaptor.Engine_v1.RecoverSigner(header)
}

// Get master nodes over extra data of previous checkpoint block.
func (adaptor *EngineAdaptor) GetMasternodesFromCheckpointHeader(preCheckpointHeader *types.Header, n, e uint64) []common.Address {
	return adaptor.Engine_v1.GetMasternodesFromCheckpointHeader(preCheckpointHeader, n, e)
}

func (adaptor *EngineAdaptor) RecoverValidator(header *types.Header) (common.Address, error) {
	return adaptor.Engine_v1.RecoverValidator(header)
}

func (adaptor *EngineAdaptor) GetBlockSigners(header *types.Header) (interface{}, bool) {
	return adaptor.GetBlockSigners(header)
}
