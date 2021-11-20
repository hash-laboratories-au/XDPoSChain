package engine_v2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/countdown"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/consensus/clique"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
	lru "github.com/hashicorp/golang-lru"
)

type XDPoS_v2 struct {
	config *params.XDPoSConfig // Consensus engine configuration parameters
	db     ethdb.Database      // Database to store and retrieve snapshot checkpoints

	recents    *lru.ARCCache // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache // Signatures of recent blocks to speed up mining

	signer   common.Address  // Ethereum address of the signing key
	signFn   clique.SignerFn // Signer function to authorize hashes with
	lock     sync.RWMutex    // Protects the signer fields
	signLock sync.RWMutex    // Protects the signer fields

	BroadcastCh   chan interface{}
	timeoutWorker *countdown.CountdownTimer // Timer to generate broadcast timeout msg if threashold reached

	timeoutPool       *utils.Pool
	votePool          *utils.Pool
	currentRound      utils.Round
	highestVotedRound utils.Round
	highestQuorumCert *utils.QuorumCert
	// LockQC in XDPoS Consensus 2.0, used in voting rule
	lockQuorumCert     *utils.QuorumCert
	highestTimeoutCert *utils.TimeoutCert
	highestCommitBlock *utils.BlockInfo

	HookReward func(chain consensus.ChainReader, state *state.StateDB, parentState *state.StateDB, header *types.Header) (error, map[string]interface{})
}

func New(config *params.XDPoSConfig, db ethdb.Database) *XDPoS_v2 {
	// Setup Timer
	duration := time.Duration(config.V2.TimeoutWorkerDuration) * time.Millisecond
	timer := countdown.NewCountDown(duration)
	timeoutPool := utils.NewPool(config.V2.CertThreshold)

	recents, _ := lru.NewARC(utils.InmemorySnapshots)
	signatures, _ := lru.NewARC(utils.InmemorySnapshots)

	votePool := utils.NewPool(config.V2.CertThreshold)
	engine := &XDPoS_v2{
		config:     config,
		db:         db,
		signatures: signatures,

		recents:       recents,
		timeoutWorker: timer,
		BroadcastCh:   make(chan interface{}),
		timeoutPool:   timeoutPool,
		votePool:      votePool,

		highestTimeoutCert: &utils.TimeoutCert{},
		highestQuorumCert:  &utils.QuorumCert{},
	}
	// Add callback to the timer
	timer.OnTimeoutFn = engine.onCountdownTimeout
	// Attach vote & timeout pool callback function when it reached threshold
	votePool.SetOnThresholdFn(engine.onVotePoolThresholdReached)
	timeoutPool.SetOnThresholdFn(engine.onTimeoutPoolThresholdReached)

	return engine
}

/*
	Testing tools
*/
func (x *XDPoS_v2) SetNewRoundFaker(newRound utils.Round, resetTimer bool) {
	// Reset a bunch of things
	if resetTimer {
		x.timeoutWorker.Reset()
	}
	x.currentRound = newRound
}

// Utils for test to check currentRound value
func (x *XDPoS_v2) GetCurrentRound() utils.Round {
	return x.currentRound
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (x *XDPoS_v2) Prepare(chain consensus.ChainReader, header *types.Header) error {
	// If the block isn't a checkpoint, cast a random vote (good enough for now)
	header.Coinbase = common.Address{}
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()
	// TODO to be confirmed
	/*

		// Assemble the voting snapshot to check which votes make sense
		snap, err := x.snapshot(chain, number-1, header.ParentHash, nil)
		if err != nil {
			return err
		}

		if number%x.config.Epoch != 0 {
			x.lock.RLock()

			// Gather all the proposals that make sense voting on
			addresses := make([]common.Address, 0, len(x.proposals))
			for address, authorize := range x.proposals {
				if snap.validVote(address, authorize) {
					addresses = append(addresses, address)
				}
			}
			// If there's pending proposals, cast a vote on them
			if len(addresses) > 0 {
				header.Coinbase = addresses[rand.Intn(len(addresses))]
				if x.proposals[header.Coinbase] {
					copy(header.Nonce[:], utils.NonceAuthVote)
				} else {
					copy(header.Nonce[:], utils.NonceDropVote)
				}
			}
			x.lock.RUnlock()
		}
	*/
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Set the correct difficulty
	header.Difficulty = x.calcDifficulty(chain, parent, x.signer)
	log.Debug("CalcDifficulty ", "number", header.Number, "difficulty", header.Difficulty)
	/*
			masternodes := snap.GetMasterNodes()
			if number >= x.config.Epoch && number%x.config.Epoch == 0 {
				if x.HookPenalty != nil || x.HookPenaltyTIPSigning != nil {
					var penMasternodes []common.Address
					var err error
					if chain.Config().IsTIPSigning(header.Number) {
						penMasternodes, err = x.HookPenaltyTIPSigning(chain, header, masternodes)
					} else {
						penMasternodes, err = x.HookPenalty(chain, number)
					}
					if err != nil {
						return err
					}
					if len(penMasternodes) > 0 {
						// penalize bad masternode(s)
						masternodes = common.RemoveItemFromArray(masternodes, penMasternodes)
						for _, address := range penMasternodes {
							log.Debug("Penalty status", "address", address, "number", number)
						}
						header.Penalties = common.ExtractAddressToBytes(penMasternodes)
					}
				}
				// Prevent penalized masternode(s) within 4 recent epochs
				for i := 1; i <= common.LimitPenaltyEpoch; i++ {
					if number > uint64(i)*x.config.Epoch {
						masternodes = removePenaltiesFromBlock(chain, masternodes, number-uint64(i)*x.config.Epoch)
					}
				}
				for _, masternode := range masternodes {
					header.Extra = append(header.Extra, masternode[:]...)
				}
				if x.HookValidator != nil {
					validators, err := x.HookValidator(header, masternodes)
					if err != nil {
						return err
					}
					header.Validators = validators
				}
			}
		if x.HookValidator != nil {
			validators, err := x.HookValidator(header, masternodes)
			if err != nil {
				return err
			}
			header.Validators = validators
		}
	*/

	extra := utils.ExtraFields_v2{
		Round:      x.currentRound,
		QuorumCert: x.highestQuorumCert,
	}

	extraByte, err := extra.EncodeToBytes()
	if err != nil {
		return err
	}

	header.Extra = extraByte

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay

	header.Time = new(big.Int).Add(parent.Time, new(big.Int).SetUint64(x.config.Period))
	if header.Time.Int64() < time.Now().Unix() {
		header.Time = big.NewInt(time.Now().Unix())
	}

	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (x *XDPoS_v2) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, parentState *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// set block reward
	number := header.Number.Uint64()
	rCheckpoint := chain.Config().XDPoS.RewardCheckpoint

	// _ = c.CacheData(header, txs, receipts)

	if x.HookReward != nil && number%rCheckpoint == 0 {
		err, rewards := x.HookReward(chain, state, parentState, header)
		if err != nil {
			return nil, err
		}
		if len(common.StoreRewardFolder) > 0 {
			data, err := json.Marshal(rewards)
			if err == nil {
				err = ioutil.WriteFile(filepath.Join(common.StoreRewardFolder, header.Number.String()+"."+header.Hash().Hex()), data, 0644)
			}
			if err != nil {
				log.Error("Error when save reward info ", "number", header.Number, "hash", header.Hash().Hex(), "err", err)
			}
		}
	}

	// the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts), nil
}

// Authorize injects a private key into the consensus engine to mint new blocks with.
func (x *XDPoS_v2) Authorize(signer common.Address, signFn clique.SignerFn) {
	x.signLock.Lock()
	defer x.signLock.Unlock()

	x.signer = signer
	x.signFn = signFn
}

func (x *XDPoS_v2) Author(header *types.Header) (common.Address, error) {
	return utils.Ecrecover(header, x.signatures)
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (x *XDPoS_v2) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return nil, utils.ErrUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	// checkpoint blocks have no tx
	if x.config.Period == 0 && len(block.Transactions()) == 0 && number%x.config.Epoch != 0 {
		return nil, utils.ErrWaitTransactions
	}
	// Don't hold the signer fields for the entire sealing procedure
	x.lock.RLock()
	signer, signFn := x.signer, x.signFn
	x.lock.RUnlock()

	// Bail out if we're unauthorized to sign a block
	snap, err := x.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return nil, err
	}
	masternodes := x.GetMasternodes(chain, header)
	if _, authorized := snap.MasterNodes[signer]; !authorized {
		valid := false
		for _, m := range masternodes {
			if m == signer {
				valid = true
				break
			}
		}
		if !valid {
			return nil, utils.ErrUnauthorized
		}
	}
	// If we're amongst the recent signers, wait for the next block
	// only check recent signers if there are more than one signer.
	/*
		if len(masternodes) > 1 {
			for seen, recent := range snap.Recents {
				if recent == signer {
					// Signer is among recents, only wait if the current block doesn't shift it out
					// There is only case that we don't allow signer to create two continuous blocks.
					if limit := uint64(2); number < limit || seen > number-limit {
						// Only take into account the non-epoch blocks
						if number%x.config.Epoch != 0 {
							log.Info("Signed recently, must wait for others ", "len(masternodes)", len(masternodes), "number", number, "limit", limit, "seen", seen, "recent", recent.String(), "snap.Recents", snap.Recents)
							<-stop
							return nil, nil
						}
					}
				}
			}
		}
	*/
	select {
	case <-stop:
		return nil, nil
	default:
	}
	// Sign all the things!
	sighash, err := signFn(accounts.Account{Address: signer}, utils.SigHash(header).Bytes())
	if err != nil {
		return nil, err
	}
	copy(header.Extra[len(header.Extra)-utils.ExtraSeal:], sighash)
	m2, err := x.GetValidator(signer, chain, header)
	if err != nil {
		return nil, fmt.Errorf("can't get block validator: %v", err)
	}
	if m2 == signer {
		header.Validator = sighash
	}
	return block.WithSeal(header), nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (x *XDPoS_v2) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return x.calcDifficulty(chain, parent, x.signer)
}

func (x *XDPoS_v2) calcDifficulty(chain consensus.ChainReader, parent *types.Header, signer common.Address) *big.Int {
	// If we're running a engine faking, skip calculation
	if x.config.SkipValidation {
		return big.NewInt(1)
	}
	len, preIndex, curIndex, _, err := x.YourTurn(chain, parent, signer)
	if err != nil {
		return big.NewInt(int64(len + curIndex - preIndex))
	}
	return big.NewInt(int64(len - utils.Hop(len, preIndex, curIndex)))
}

func (x *XDPoS_v2) YourTurn(chain consensus.ChainReader, parent *types.Header, signer common.Address) (int, int, int, bool, error) {
	masternodes := x.GetMasternodes(chain, parent)

	snap, err := x.GetSnapshot(chain, parent)
	if err != nil {
		log.Warn("Failed when trying to commit new work", "err", err)
		return 0, -1, -1, false, err
	}
	if len(masternodes) == 0 {
		return 0, -1, -1, false, errors.New("Masternodes not found")
	}
	pre := common.Address{}
	// masternode[0] has chance to create block 1
	preIndex := -1
	if parent.Number.Uint64() != 0 {
		pre, err = whoIsCreator(snap, parent)
		if err != nil {
			return 0, 0, 0, false, err
		}
		preIndex = utils.Position(masternodes, pre)
	}
	curIndex := utils.Position(masternodes, signer)
	if signer == x.signer {
		log.Debug("Masternodes cycle info", "number of masternodes", len(masternodes), "previous", pre, "position", preIndex, "current", signer, "position", curIndex)
	}
	for i, s := range masternodes {
		log.Debug("Masternode:", "index", i, "address", s.String())
	}
	if (preIndex+1)%len(masternodes) == curIndex {
		return len(masternodes), preIndex, curIndex, true, nil
	}
	return len(masternodes), preIndex, curIndex, false, nil
}

func whoIsCreator(snap *SnapshotV2, header *types.Header) (common.Address, error) {
	if header.Number.Uint64() == 0 {
		return common.Address{}, errors.New("Don't take block 0")
	}
	m, err := utils.Ecrecover(header, snap.sigcache)
	if err != nil {
		return common.Address{}, err
	}
	return m, nil
}

func (x *XDPoS_v2) GetMasternodes(chain consensus.ChainReader, header *types.Header) []common.Address {
	n := header.Number.Uint64()
	e := x.config.Epoch
	switch {
	case n%e == 0:
		return utils.GetMasternodesFromCheckpointHeader(header)
	case n%e != 0:
		h := chain.GetHeaderByNumber(n - (n % e))
		return utils.GetMasternodesFromCheckpointHeader(h)
	default:
		return []common.Address{}
	}
}

func (x *XDPoS_v2) GetValidator(creator common.Address, chain consensus.ChainReader, header *types.Header) (common.Address, error) {
	epoch := x.config.Epoch
	no := header.Number.Uint64()
	cpNo := no
	if no%epoch != 0 {
		cpNo = no - (no % epoch)
	}
	if cpNo == 0 {
		return common.Address{}, nil
	}
	cpHeader := chain.GetHeaderByNumber(cpNo)
	if cpHeader == nil {
		if no%epoch == 0 {
			cpHeader = header
		} else {
			return common.Address{}, fmt.Errorf("couldn't find checkpoint header")
		}
	}
	m, err := utils.GetM1M2FromCheckpointHeader(cpHeader, header, chain.Config())
	if err != nil {
		return common.Address{}, err
	}
	return m[creator], nil
}

func (x *XDPoS_v2) GetSnapshot(chain consensus.ChainReader, header *types.Header) (*SnapshotV2, error) {
	number := header.Number.Uint64()
	log.Trace("get snapshot", "number", number, "hash", header.Hash())
	snap, err := x.snapshot(chain, number, header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap, nil
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (x *XDPoS_v2) snapshot(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*SnapshotV2, error) {
	// Search for a SnapshotV2 in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *SnapshotV2
	)
	for snap == nil {
		// If an in-memory SnapshotV2 was found, use that
		if s, ok := x.recents.Get(hash); ok {
			snap = s.(*SnapshotV2)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		// checkpoint snapshot = checkpoint - gap
		if (number+x.config.Gap)%x.config.Epoch == 0 {
			if s, err := loadSnapshot(x.config, x.signatures, x.db, hash); err == nil {
				log.Trace("Loaded snapshot form disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}
		// If we're at block zero, make a snapshot
		if number == 0 {
			genesis := chain.GetHeaderByNumber(0)
			if err := x.VerifyHeader(chain, genesis, true); err != nil {
				return nil, err
			}
			signers := make([]common.Address, (len(genesis.Extra)-utils.ExtraVanity-utils.ExtraSeal)/common.AddressLength)
			for i := 0; i < len(signers); i++ {
				copy(signers[i][:], genesis.Extra[utils.ExtraVanity+i*common.AddressLength:])
			}
			snap = newSnapshot(x.config, x.signatures, 0, genesis.Hash(), x.currentRound, x.highestQuorumCert, signers)
			if err := snap.store(x.db); err != nil {
				return nil, err
			}
			log.Trace("Stored genesis voting snapshot to disk")
			break
		}
		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers)
	if err != nil {
		return nil, err
	}
	x.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%x.config.Epoch == x.config.Gap {
		if err = snap.store(x.db); err != nil {
			return nil, err
		}
		log.Trace("Stored snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

func (x *XDPoS_v2) VerifyHeader(chain consensus.ChainReader, header *types.Header, fullVerify bool) error {
	return nil
}

/*
	SyncInfo workflow
*/
// Verify syncInfo and trigger process QC or TC if successful
func (x *XDPoS_v2) VerifySyncInfoMessage(syncInfo utils.SyncInfo) error {
	/*
		1. Verify items including:
				- verifyQC
				- verifyTC
		2. Broadcast(Not part of consensus)
	*/
	err := x.verifyQC(syncInfo.HighestQuorumCert)
	if err != nil {
		log.Warn("SyncInfo message verification failed due to QC", err)
		return err
	}
	err = x.verifyTC(syncInfo.HighestTimeoutCert)
	if err != nil {
		log.Warn("SyncInfo message verification failed due to TC", err)
		return err
	}
	return nil
}

func (x *XDPoS_v2) SyncInfoHandler(header *types.Header) error {
	/*
		1. processQC
		2. processTC
	*/
	return nil
}

/*
	Vote workflow
*/
func (x *XDPoS_v2) VerifyVoteMessage(vote utils.Vote) (bool, error) {
	/*
		  1. Check signature:
					- Use ecRecover to get the public key
					- Use the above public key to find out the xdc address
					- Use the above xdc address to check against the master node list(For the running epoch)
			2. Verify blockInfo
			3. Broadcast(Not part of consensus)
	*/
	return x.verifyMsgSignature(utils.VoteSigHash(vote.ProposedBlockInfo), vote.Signature)
}

// Consensus entry point for processing vote message to produce QC
func (x *XDPoS_v2) VoteHandler(voteMsg utils.Vote) error {
	x.lock.Lock()
	defer x.lock.Unlock()

	// 1. checkRoundNumber
	if voteMsg.ProposedBlockInfo.Round != x.currentRound {
		return fmt.Errorf("Vote message round number: %v does not match currentRound: %v", voteMsg.ProposedBlockInfo.Round, x.currentRound)
	}

	// Collect vote
	thresholdReached, numberOfVotesInPool, hookError := x.votePool.Add(&voteMsg)
	if hookError != nil {
		log.Error("Error while adding vote message to the pool, ", hookError)
		return hookError
	}

	log.Debug("Vote pool threashold reached: %v, number of items in the pool: %v", thresholdReached, numberOfVotesInPool)
	return nil
}

/*
	Function that will be called by votePool when it reached threshold.
	In the engine v2, we will need to generate and process QC
*/
func (x *XDPoS_v2) onVotePoolThresholdReached(pooledVotes map[common.Hash]utils.PoolObj, currentVoteMsg utils.PoolObj) error {
	signatures := []utils.Signature{}
	for _, v := range pooledVotes {
		signatures = append(signatures, v.(*utils.Vote).Signature)
	}
	// Genrate QC
	quorumCert := &utils.QuorumCert{
		ProposedBlockInfo: currentVoteMsg.(*utils.Vote).ProposedBlockInfo,
		Signatures:        signatures,
	}
	err := x.processQC(quorumCert)
	if err != nil {
		log.Error("Error while processing QC in the Vote handler after reaching pool threshold, ", err)
		return err
	}
	log.Info("🗳 Successfully processed the vote and produced QC!")
	return nil
}

/*
	Timeout workflow
*/
// Verify timeout message type from peers in bft.go
/*
	  1. Check signature:
				- Use ecRecover to get the public key
				- Use the above public key to find out the xdc address
				- Use the above xdc address to check against the master node(For the running epoch)
		2. Broadcast(Not part of consensus)
*/
func (x *XDPoS_v2) VerifyTimeoutMessage(timeoutMsg utils.Timeout) (bool, error) {
	return x.verifyMsgSignature(utils.TimeoutSigHash(&timeoutMsg.Round), timeoutMsg.Signature)
}

/*
	Entry point for handling timeout message to process below:
	1. checkRoundNumber()
	2. Collect timeout
	Once timeout pool reached threshold, it will trigger the call to the hook function "onTimeoutPoolThresholdReached"
*/
func (x *XDPoS_v2) TimeoutHandler(timeout *utils.Timeout) error {
	x.lock.Lock()
	defer x.lock.Unlock()

	// 1. checkRoundNumber
	if timeout.Round != x.currentRound {
		return fmt.Errorf("Timeout message round number: %v does not match currentRound: %v", timeout.Round, x.currentRound)
	}
	// Collect timeout, generate TC
	isThresholdReached, numberOfTimeoutsInPool, hookError := x.timeoutPool.Add(timeout)
	if hookError != nil {
		log.Error("Error adding timeout to the pool, ", hookError.Error())
		return hookError
	}
	log.Debug("Timeout pool threashold reached: %v, number of items in the pool: %v", isThresholdReached, numberOfTimeoutsInPool)
	return nil
}

/*
	Function that will be called by timeoutPool when it reached threshold.
	In the engine v2, we will need to:
		1. Genrate TC
		2. processTC()
		3. generateSyncInfo()
*/
func (x *XDPoS_v2) onTimeoutPoolThresholdReached(pooledTimeouts map[common.Hash]utils.PoolObj, currentTimeoutMsg utils.PoolObj) error {
	signatures := []utils.Signature{}
	for _, v := range pooledTimeouts {
		signatures = append(signatures, v.(*utils.Timeout).Signature)
	}
	// Genrate TC
	timeoutCert := &utils.TimeoutCert{
		Round:      currentTimeoutMsg.(*utils.Timeout).Round,
		Signatures: signatures,
	}
	// Process TC
	err := x.processTC(timeoutCert)
	if err != nil {
		log.Error("Error while processing TC in the Timeout handler after reaching pool threshold, ", err.Error())
		return err
	}
	// Generate and broadcast syncInfo
	syncInfo := x.getSyncInfo()
	x.broadcastToBftChannel(syncInfo)

	log.Info("⏰ Successfully processed the timeout message and produced TC & SyncInfo!")
	return nil
}

/*
	Process Block workflow
*/
func (x *XDPoS_v2) ProcessBlockHandler() {
	/*
		1. processQC()
		2. verifyVotingRule()
		3. sendVote()

	*/
}

/*
	QC & TC Utils
*/

// Genrate blockInfo which contains Hash, round and blockNumber and send to queue
func (x *XDPoS_v2) generateBlockInfo() error {
	return nil
}

// To be used by different message verification. Verify local DB block info against the received block information(i.e hash, blockNum, round)
func (x *XDPoS_v2) VerifyBlockInfo(blockInfo utils.BlockInfo) error {
	return nil
}

func (x *XDPoS_v2) verifyQC(quorumCert *utils.QuorumCert) error {
	/*
		1. Verify signer signatures: (List of signatures)
					- Use ecRecover to get the public key
					- Use the above public key to find out the xdc address
					- Use the above xdc address to check against the master node list(For the received QC epoch)
		2. Verify blockInfo
	*/
	return nil
}

func (x *XDPoS_v2) verifyTC(timeoutCert *utils.TimeoutCert) error {
	/*
		1. Verify signer signature: (List of signatures)
					- Use ecRecover to get the public key
					- Use the above public key to find out the xdc address
					- Use the above xdc address to check against the master node list(For the received TC epoch)
	*/
	return nil
}

// Update local QC variables including highestQC & lockQC, as well as update commit blockInfo before call
/*
	1. Update HighestQC and LockQC
	2. Update commit block info (TODO)
	3. Check QC round >= node's currentRound. If yes, call setNewRound
*/
func (x *XDPoS_v2) processQC(quorumCert *utils.QuorumCert) error {
	if x.highestQuorumCert == nil || quorumCert.ProposedBlockInfo.Round > x.highestQuorumCert.ProposedBlockInfo.Round {
		x.highestQuorumCert = quorumCert
		//TODO: do I need a clone?
	}
	//TODO: x.blockchain.getBlock(quorumCert.ProposedBlockInfo.Hash) then get the QC inside that block header
	//TODO: update lockQC
	//TODO: find parent and grandparent and grandgrandparent block, check round number, if so, commit grandgrandparent
	if quorumCert.ProposedBlockInfo.Round >= x.currentRound {
		x.setNewRound(quorumCert.ProposedBlockInfo.Round + 1)
	}
	return nil
}

/*
	1. Update highestTC
	2. Check TC round >= node's currentRound. If yes, call setNewRound
*/
func (x *XDPoS_v2) processTC(timeoutCert *utils.TimeoutCert) error {
	if x.highestTimeoutCert == nil || timeoutCert.Round > x.highestTimeoutCert.Round {
		x.highestTimeoutCert = timeoutCert
	}
	if timeoutCert.Round >= x.currentRound {
		err := x.setNewRound(timeoutCert.Round + 1)
		if err != nil {
			return err
		}
	}
	return nil
}

/*
	1. Set currentRound = QC round + 1 (or TC round +1)
	2. Reset timer
	3. Reset vote and timeout Pools
*/
func (x *XDPoS_v2) setNewRound(round utils.Round) error {
	x.currentRound = round
	//TODO: tell miner now it's a new round and start mine if it's leader
	x.timeoutWorker.Reset()
	//TODO: vote pools
	x.timeoutPool.Clear()
	return nil
}

// Hot stuff rule to decide whether this node is eligible to vote for the received block
func (x *XDPoS_v2) verifyVotingRule(header *types.Header) error {
	/*
		Make sure this node has not voted for this round. We can have a variable highestVotedRound, and check currentRound > highestVotedRound.
		HotStuff Voting rule:
		header's round == local current round, AND (one of the following two:)
		header's block extends LockQC's ProposedBlockInfo (we need a isExtending(block_a, block_b) function), OR
		header's QC's ProposedBlockInfo.Round > LockQC's ProposedBlockInfo.Round
	*/
	return nil
}

// Once Hot stuff voting rule has verified, this node can then send vote
func (x *XDPoS_v2) sendVote(blockInfo *utils.BlockInfo) error {
	// First step: Generate the signature by using node's private key(The signature is the blockInfo signature)
	// Second step: Construct the vote struct with the above signature & blockinfo struct
	// Third step: Send the vote to broadcast channel
	signedHash, err := x.signSignature(utils.VoteSigHash(blockInfo))
	if err != nil {
		return err
	}
	voteMsg := &utils.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         signedHash,
	}
	x.broadcastToBftChannel(voteMsg)
	return nil
}

// Generate and send timeout into BFT channel.
/*
	1. timeout.round = currentRound
	2. Sign the signature
	3. send to broadcast channel
*/
func (x *XDPoS_v2) sendTimeout() error {
	signedHash, err := x.signSignature(utils.TimeoutSigHash(&x.currentRound))
	if err != nil {
		return err
	}
	timeoutMsg := &utils.Timeout{
		Round:     x.currentRound,
		Signature: signedHash,
	}
	x.broadcastToBftChannel(timeoutMsg)
	return nil
}

// Generate and send syncInfo into Broadcast channel. The SyncInfo includes local highest QC & TC
func (x *XDPoS_v2) sendSyncInfo() error {
	return nil
}

func (x *XDPoS_v2) signSignature(signingHash common.Hash) (utils.Signature, error) {
	// Don't hold the signFn for the whole signing operation
	x.signLock.RLock()
	signer, signFn := x.signer, x.signFn
	x.signLock.RUnlock()

	signedHash, err := signFn(accounts.Account{Address: signer}, signingHash.Bytes())
	if err != nil {
		return nil, fmt.Errorf("Error while signing hash")
	}
	return signedHash, nil
}

func (x *XDPoS_v2) verifyMsgSignature(signedHashToBeVerified common.Hash, signature utils.Signature) (bool, error) {
	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(signedHashToBeVerified.Bytes(), signature)
	if err != nil {
		return false, fmt.Errorf("Error while verifying message: %v", err)
	}
	var signerAddress common.Address
	copy(signerAddress[:], crypto.Keccak256(pubkey[1:])[12:])
	masternodes := x.getCurrentRoundMasterNodes()
	for _, mn := range masternodes {
		if mn == signerAddress {
			return true, nil
		}
	}

	return false, fmt.Errorf("Masternodes does not contain signer address. Master node list %v, Signer address: %v", masternodes, signerAddress)
}

/*
	Function that will be called by timer when countdown reaches its threshold.
	In the engine v2, we would need to broadcast timeout messages to other peers
*/
func (x *XDPoS_v2) onCountdownTimeout(time time.Time) error {
	x.lock.Lock()
	defer x.lock.Unlock()

	err := x.sendTimeout()
	if err != nil {
		log.Error("Error while sending out timeout message at time: ", time)
		return err
	}
	return nil
}

func (x *XDPoS_v2) broadcastToBftChannel(msg interface{}) {
	go func() {
		x.BroadcastCh <- msg
	}()
}

func (x *XDPoS_v2) getCurrentRoundMasterNodes() []common.Address {
	return []common.Address{}
}

// methods for testing
func (x *XDPoS_v2) SetHighestQuorumCert(qc *utils.QuorumCert) {
	x.highestQuorumCert = qc
}

func (x *XDPoS_v2) getSyncInfo() utils.SyncInfo {
	return utils.SyncInfo{
		HighestQuorumCert:  x.highestQuorumCert,
		HighestTimeoutCert: x.highestTimeoutCert,
	}
}
