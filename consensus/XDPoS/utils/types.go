package utils

import (
	"fmt"
	"math/big"
	"time"

	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/XDCxlending/lendingstate"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/clique"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

type Masternode struct {
	Address common.Address
	Stake   *big.Int
}

type TradingService interface {
	GetTradingStateRoot(block *types.Block, author common.Address) (common.Hash, error)
	GetTradingState(block *types.Block, author common.Address) (*tradingstate.TradingStateDB, error)
	HasTradingState(block *types.Block, author common.Address) bool
	GetStateCache() tradingstate.Database
	GetTriegc() *prque.Prque
	ApplyOrder(header *types.Header, coinbase common.Address, chain consensus.ChainContext, statedb *state.StateDB, XDCXstatedb *tradingstate.TradingStateDB, orderBook common.Hash, order *tradingstate.OrderItem) ([]map[string]string, []*tradingstate.OrderItem, error)
	UpdateMediumPriceBeforeEpoch(epochNumber uint64, tradingStateDB *tradingstate.TradingStateDB, statedb *state.StateDB) error
	IsSDKNode() bool
	SyncDataToSDKNode(takerOrder *tradingstate.OrderItem, txHash common.Hash, txMatchTime time.Time, statedb *state.StateDB, trades []map[string]string, rejectedOrders []*tradingstate.OrderItem, dirtyOrderCount *uint64) error
	RollbackReorgTxMatch(txhash common.Hash) error
	GetTokenDecimal(chain consensus.ChainContext, statedb *state.StateDB, tokenAddr common.Address) (*big.Int, error)
}

type LendingService interface {
	GetLendingStateRoot(block *types.Block, author common.Address) (common.Hash, error)
	GetLendingState(block *types.Block, author common.Address) (*lendingstate.LendingStateDB, error)
	HasLendingState(block *types.Block, author common.Address) bool
	GetStateCache() lendingstate.Database
	GetTriegc() *prque.Prque
	ApplyOrder(header *types.Header, coinbase common.Address, chain consensus.ChainContext, statedb *state.StateDB, lendingStateDB *lendingstate.LendingStateDB, tradingStateDb *tradingstate.TradingStateDB, lendingOrderBook common.Hash, order *lendingstate.LendingItem) ([]*lendingstate.LendingTrade, []*lendingstate.LendingItem, error)
	GetCollateralPrices(header *types.Header, chain consensus.ChainContext, statedb *state.StateDB, tradingStateDb *tradingstate.TradingStateDB, collateralToken common.Address, lendingToken common.Address) (*big.Int, *big.Int, error)
	GetMediumTradePriceBeforeEpoch(chain consensus.ChainContext, statedb *state.StateDB, tradingStateDb *tradingstate.TradingStateDB, baseToken common.Address, quoteToken common.Address) (*big.Int, error)
	ProcessLiquidationData(header *types.Header, chain consensus.ChainContext, statedb *state.StateDB, tradingState *tradingstate.TradingStateDB, lendingState *lendingstate.LendingStateDB) (updatedTrades map[common.Hash]*lendingstate.LendingTrade, liquidatedTrades, autoRepayTrades, autoTopUpTrades, autoRecallTrades []*lendingstate.LendingTrade, err error)
	SyncDataToSDKNode(chain consensus.ChainContext, state *state.StateDB, block *types.Block, takerOrderInTx *lendingstate.LendingItem, txHash common.Hash, txMatchTime time.Time, trades []*lendingstate.LendingTrade, rejectedOrders []*lendingstate.LendingItem, dirtyOrderCount *uint64) error
	UpdateLiquidatedTrade(blockTime uint64, result lendingstate.FinalizedResult, trades map[common.Hash]*lendingstate.LendingTrade) error
	RollbackLendingData(txhash common.Hash) error
}

type PublicApiSnapshot struct {
	Number  uint64                          `json:"number"`  // Block number where the snapshot was created
	Hash    common.Hash                     `json:"hash"`    // Block hash where the snapshot was created
	Signers map[common.Address]struct{}     `json:"signers"` // Set of authorized signers at this moment
	Recents map[uint64]common.Address       `json:"recents"` // Set of recent signers for spam protections
	Votes   []*clique.Vote                  `json:"votes"`   // List of votes cast in chronological order
	Tally   map[common.Address]clique.Tally `json:"tally"`   // Current vote tally to avoid recalculating
}

// Vote message in XDPoS 2.0
type VoteType struct {
	ProposedBlockInfo BlockInfo
	Signature         []byte
}

// Timeout message in XDPoS 2.0
type TimeoutType struct {
	Round     uint64
	Signature []byte
}

// BFT Sync Info message in XDPoS 2.0
type SyncInfoType struct {
	HighestQuorumCert  QuorumCertType
	HighestTimeoutCert TimeoutCertType
}

// Block Info struct in XDPoS 2.0, used for vote message, etc.
type BlockInfo struct {
	Hash   common.Hash `json:"hash"`
	Round  uint64      `json:"round"`
	Number *big.Int    `json:"number"`
}

// Quorum Certificate struct in XDPoS 2.0
type QuorumCertType struct {
	ProposedBlockInfo BlockInfo `json:"proposedBlock"`
	Signatures        []byte    `json:"signatures"`
}

// Timeout Certificate struct in XDPoS 2.0
type TimeoutCertType struct {
	Round      uint64
	Signatures []byte
}

// The parsed extra fields in block header in XDPoS 2.0 (excluding the version byte)
// (The version (consensus version) byte is the first byte in header's extra) and it's only valid with value >= 2)
type ExtraFields_v2 struct {
	Round      uint64
	QuorumCert QuorumCertType
}

func (e *ExtraFields_v2) EncodeToBytes() ([]byte, error) {
	bytes, err := rlp.EncodeToBytes(e)
	if err != nil {
		return nil, err
	}
	versionByte := []byte{2}
	return append(versionByte, bytes...), nil
}

func DecodeBytesExtraFields(b []byte, val interface{}) error {
	//question shall this be specific to version 2? or all versions>=2?
	if len(b) == 0 {
		return fmt.Errorf("extra field is 0 length")
	}
	return rlp.DecodeBytes(b[1:], val)
}