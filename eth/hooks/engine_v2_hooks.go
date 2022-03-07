package hooks

import (
	"errors"
	"math/big"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/contracts"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/util"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func AttachConsensusV2Hooks(adaptor *XDPoS.XDPoS, bc *core.BlockChain, chainConfig *params.ChainConfig) {
	// Hook scans for bad masternodes and decide to penalty them
	adaptor.EngineV2.HookPenalty = func(chain consensus.ChainReader, number *big.Int, parentHash common.Hash, candidates []common.Address) ([]common.Address, error) {
		start := time.Now()
		listBlockHash := make([]common.Hash, chain.Config().XDPoS.Epoch)

		// get list block hash & stats total created block
		statMiners := make(map[common.Address]int)
		listBlockHash[0] = parentHash
		parentNumber := number.Uint64() - 1
		pHash := parentHash
		for i := uint64(1); ; i++ {
			parentHeader := chain.GetHeader(pHash, parentNumber)
			b, _, err := adaptor.EngineV2.IsEpochSwitch(parentHeader)
			if err != nil {
				log.Error("[HookPenalty]", "err", err)
				return []common.Address{}, err
			}
			if b {
				break
			}
			miner := parentHeader.Coinbase // we can directly use coinbase, since it's verified (Verification is a TODO)
			value, exist := statMiners[miner]
			if exist {
				value = value + 1
			} else {
				value = 1
			}
			statMiners[miner] = value
			pHash = parentHeader.ParentHash
			parentNumber--
			listBlockHash[i] = pHash
		}

		// add list not miner to penalties
		preMasternodes := adaptor.EngineV2.GetMasternodesByHash(chain, parentHash)
		penalties := []common.Address{}
		for miner, total := range statMiners {
			if total < common.MinimunMinerBlockPerEpoch {
				log.Debug("Find a node not enough requirement create block", "addr", miner.Hex(), "total", total)
				penalties = append(penalties, miner)
			}
		}
		for _, addr := range preMasternodes {
			if _, exist := statMiners[addr]; !exist {
				log.Debug("Find a node don't create block", "addr", addr.Hex())
				penalties = append(penalties, addr)
			}
		}

		// get list check penalties signing block & list master nodes wil comeback
		// start to calc comeback at v2 block + limitPenaltyEpoch to avoid reading v1 blocks
		comebackHeight := (common.LimitPenaltyEpoch+1)*chain.Config().XDPoS.Epoch + chain.Config().XDPoS.V2.SwitchBlock.Uint64()
		penComebacks := []common.Address{}
		if number.Uint64() > comebackHeight {
			pens := adaptor.EngineV2.GetPreviousPenaltyByHash(chain, parentHash, common.LimitPenaltyEpoch)
			for _, p := range pens {
				for _, addr := range candidates {
					if p == addr {
						penComebacks = append(penComebacks, p)
						break
					}
				}
			}
		}

		// Loop for each block to check missing sign. with comeback nodes
		mapBlockHash := map[common.Hash]bool{}
		startRange := common.RangeReturnSigner - 1
		// to prevent visiting outside index of listBlockHash
		if startRange >= len(listBlockHash) {
			startRange = len(listBlockHash) - 1
		}
		for i := startRange; i >= 0; i-- {
			if len(penComebacks) > 0 {
				blockNumber := number.Uint64() - uint64(i) - 1
				bhash := listBlockHash[i]
				if blockNumber%common.MergeSignRange == 0 {
					mapBlockHash[bhash] = true
				}
				signData, ok := adaptor.GetCachedSigningTxs(bhash)
				if !ok {
					block := chain.GetBlock(bhash, blockNumber)
					txs := block.Transactions()
					signData = adaptor.CacheSigningTxs(bhash, txs)
				}
				txs := signData.([]*types.Transaction)
				// Check signer signed?
				for _, tx := range txs {
					blkHash := common.BytesToHash(tx.Data()[len(tx.Data())-32:])
					from := *tx.From()
					if mapBlockHash[blkHash] {
						for j, addr := range penComebacks {
							if from == addr {
								// Remove it from dupSigners.
								penComebacks = append(penComebacks[:j], penComebacks[j+1:]...)
								break
							}
						}
					}
				}
			} else {
				break
			}
		}

		log.Debug("Time Calculated HookPenaltyV2 ", "block", number, "pen comeback nodes", len(penComebacks), "not enough miner", len(penalties), "time", common.PrettyDuration(time.Since(start)))
		for _, comeback := range penComebacks {
			ok := true
			for _, p := range penalties {
				if p == comeback {
					ok = false
					break
				}
			}
			if ok {
				penalties = append(penalties, comeback)
			}
		}
		return penalties, nil
	}

	// Hook calculates reward for masternodes
	adaptor.EngineV2.HookReward = func(chain consensus.ChainReader, stateBlock *state.StateDB, parentState *state.StateDB, header *types.Header) (map[string]interface{}, error) {
		number := header.Number.Uint64()
		foundationWalletAddr := chain.Config().XDPoS.FoudationWalletAddr
		if foundationWalletAddr == (common.Address{}) {
			log.Error("Foundation Wallet Address is empty", "error", foundationWalletAddr)
			return nil, errors.New("foundation wallet address is empty")
		}
		rewards := make(map[string]interface{})
		// skip hook reward if this is the first v2
		if number == chain.Config().XDPoS.V2.SwitchBlock.Uint64()+1 {
			return rewards, nil
		}
		start := time.Now()
		// Get reward inflation.
		chainReward := new(big.Int).Mul(new(big.Int).SetUint64(chain.Config().XDPoS.Reward), new(big.Int).SetUint64(params.Ether))
		chainReward = util.RewardInflation(chain, chainReward, number, common.BlocksPerYear)

		// Get signers/signing tx count
		totalSigner := new(uint64)
		signers, err := GetSigningTxCount(adaptor, chain, header, totalSigner)

		log.Debug("Time Get Signers", "block", header.Number.Uint64(), "time", common.PrettyDuration(time.Since(start)))
		if err != nil {
			log.Error("[HookReward] Fail to get signers count for reward checkpoint", "error", err)
			return nil, err
		}
		rewards["signers"] = signers
		rewardSigners, err := contracts.CalculateRewardForSigner(chainReward, signers, *totalSigner)
		if err != nil {
			log.Error("[HookReward] Fail to calculate reward for signers", "error", err)
			return nil, err
		}
		// Add reward for coin holders.
		voterResults := make(map[common.Address]interface{})
		if len(signers) > 0 {
			for signer, calcReward := range rewardSigners {
				err, rewards := contracts.CalculateRewardForHolders(foundationWalletAddr, parentState, signer, calcReward, number)
				if err != nil {
					log.Error("[HookReward] Fail to calculate reward for holders.", "error", err)
					return nil, err
				}
				if len(rewards) > 0 {
					for holder, reward := range rewards {
						stateBlock.AddBalance(holder, reward)
					}
				}
				voterResults[signer] = rewards
			}
		}
		rewards["rewards"] = voterResults
		log.Debug("Time Calculated HookReward ", "block", header.Number.Uint64(), "time", common.PrettyDuration(time.Since(start)))
		return rewards, nil
	}
}

// get signing transaction sender count
func GetSigningTxCount(c *XDPoS.XDPoS, chain consensus.ChainReader, header *types.Header, totalSigner *uint64) (map[common.Address]*contracts.RewardLog, error) {
	// header should be a new epoch switch block
	number := header.Number.Uint64()
	rewardEpochCount := 2
	signEpochCount := 1
	signers := make(map[common.Address]*contracts.RewardLog)
	mapBlkHash := map[uint64]common.Hash{}

	data := make(map[common.Hash][]common.Address)
	epochCount := 0
	var masternodes []common.Address
	var startBlockNumber, endBlockNumber uint64
	for i := number - 1; ; i-- {
		header = chain.GetHeader(header.ParentHash, i)
		isEpochSwitch, _, err := c.IsEpochSwitch(header)
		if err != nil {
			return nil, err
		}
		if isEpochSwitch && i != chain.Config().XDPoS.V2.SwitchBlock.Uint64()+1 {
			epochCount += 1
			if epochCount == signEpochCount {
				endBlockNumber = header.Number.Uint64() - 1
			}
			if epochCount == rewardEpochCount {
				startBlockNumber = header.Number.Uint64() + 1
				masternodes = c.GetMasternodesFromCheckpointHeader(header)
				break
			}
		}
		mapBlkHash[i] = header.Hash()
		signData, ok := c.GetCachedSigningTxs(header.Hash())
		if !ok {
			log.Debug("Failed get from cached", "hash", header.Hash().String(), "number", i)
			block := chain.GetBlock(header.Hash(), i)
			txs := block.Transactions()
			signData = c.CacheSigningTxs(header.Hash(), txs)
		}
		txs := signData.([]*types.Transaction)
		for _, tx := range txs {
			blkHash := common.BytesToHash(tx.Data()[len(tx.Data())-32:])
			from := *tx.From()
			data[blkHash] = append(data[blkHash], from)
		}
	}

	for i := startBlockNumber; i <= endBlockNumber; i++ {
		if i%common.MergeSignRange == 0 {
			addrs := data[mapBlkHash[i]]
			// Filter duplicate address.
			if len(addrs) > 0 {
				addrSigners := make(map[common.Address]bool)
				for _, masternode := range masternodes {
					for _, addr := range addrs {
						if addr == masternode {
							if _, ok := addrSigners[addr]; !ok {
								addrSigners[addr] = true
							}
							break
						}
					}
				}

				for addr := range addrSigners {
					_, exist := signers[addr]
					if exist {
						signers[addr].Sign++
					} else {
						signers[addr] = &contracts.RewardLog{Sign: 1, Reward: new(big.Int)}
					}
					*totalSigner++
				}
			}
		}
	}

	log.Info("Calculate reward at checkpoint", "startBlock", startBlockNumber, "endBlock", endBlockNumber)

	return signers, nil
}