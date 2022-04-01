package engine_v2

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/log"
)

func (x *XDPoS_v2) timeoutHandler(blockChainReader consensus.ChainReader, timeout *utils.Timeout) error {
	// 1. checkRoundNumber
	if timeout.Round != x.currentRound {
		return &utils.ErrIncomingMessageRoundNotEqualCurrentRound{
			Type:          "timeout",
			IncomingRound: timeout.Round,
			CurrentRound:  x.currentRound,
		}
	}
	// Collect timeout, generate TC
	isThresholdReached, numberOfTimeoutsInPool, pooledTimeouts := x.timeoutPool.Add(timeout)
	log.Info("[timeoutHandler] collect timeout", "number", numberOfTimeoutsInPool)

	// Threshold reached
	if isThresholdReached {
		log.Info(fmt.Sprintf("Timeout pool threashold reached: %v, number of items in the pool: %v", isThresholdReached, numberOfTimeoutsInPool))
		err := x.onTimeoutPoolThresholdReached(blockChainReader, pooledTimeouts, timeout, timeout.GapNumber)
		if err != nil {
			return err
		}
		// clean up timeout message, regardless its GapNumber or round
		x.timeoutPool.Clear()
	}
	return nil
}

/*
	Function that will be called by timeoutPool when it reached threshold.
	In the engine v2, we will need to:
		1. Genrate TC
		2. processTC()
		3. generateSyncInfo()
*/
func (x *XDPoS_v2) onTimeoutPoolThresholdReached(blockChainReader consensus.ChainReader, pooledTimeouts map[common.Hash]utils.PoolObj, currentTimeoutMsg utils.PoolObj, gapNumber uint64) error {
	signatures := []utils.Signature{}
	for _, v := range pooledTimeouts {
		signatures = append(signatures, v.(*utils.Timeout).Signature)
	}
	// Genrate TC
	timeoutCert := &utils.TimeoutCert{
		Round:      currentTimeoutMsg.(*utils.Timeout).Round,
		Signatures: signatures,
		GapNumber:  gapNumber,
	}
	// Process TC
	err := x.processTC(blockChainReader, timeoutCert)
	if err != nil {
		log.Error("Error while processing TC in the Timeout handler after reaching pool threshold", "TcRound", timeoutCert.Round, "NumberOfTcSig", len(timeoutCert.Signatures), "GapNumber", gapNumber, "Error", err)
		return err
	}
	// Generate and broadcast syncInfo
	syncInfo := x.getSyncInfo()
	x.broadcastToBftChannel(syncInfo)

	log.Info("Successfully processed the timeout message and produced TC & SyncInfo!", "TcRound", timeoutCert.Round, "NumberOfTcSig", len(timeoutCert.Signatures))
	return nil
}

func (x *XDPoS_v2) verifyTC(chain consensus.ChainReader, timeoutCert *utils.TimeoutCert) error {
	/*
		1. Get epoch master node list by gapNumber
		2. Check number of signatures > threshold, as well as it's format. (Same as verifyQC)
		2. Verify signer signature: (List of signatures)
					- Use ecRecover to get the public key
					- Use the above public key to find out the xdc address
					- Use the above xdc address to check against the master node list from step 1(For the received TC epoch)
	*/
	snap, err := x.getSnapshot(chain, timeoutCert.GapNumber, true)
	if err != nil {
		log.Error("[verifyTC] Fail to get snapshot when verifying TC!", "TCGapNumber", timeoutCert.GapNumber)
		return fmt.Errorf("[verifyTC] Unable to get snapshot")
	}
	if snap == nil || len(snap.NextEpochMasterNodes) == 0 {
		log.Error("[verifyTC] Something wrong with the snapshot from gapNumber", "messageGapNumber", timeoutCert.GapNumber, "snapshot", snap)
		return fmt.Errorf("Empty master node lists from snapshot")
	}

	if timeoutCert == nil {
		log.Warn("[verifyTC] TC is Nil")
		return utils.ErrInvalidTC
	} else if timeoutCert.Signatures == nil || (len(timeoutCert.Signatures) < x.config.V2.CertThreshold) {
		log.Warn("[verifyTC] Invalid TC Signature is nil or empty", "timeoutCert.Round", timeoutCert.Round, "timeoutCert.GapNumber", timeoutCert.GapNumber, "Signatures len", len(timeoutCert.Signatures))
		return utils.ErrInvalidTC
	}

	var wg sync.WaitGroup
	wg.Add(len(timeoutCert.Signatures))
	var haveError error

	signedTimeoutObj := utils.TimeoutSigHash(&utils.TimeoutForSign{
		Round:     timeoutCert.Round,
		GapNumber: timeoutCert.GapNumber,
	})

	for _, signature := range timeoutCert.Signatures {
		go func(sig utils.Signature) {
			defer wg.Done()
			verified, _, err := x.verifyMsgSignature(signedTimeoutObj, sig, snap.NextEpochMasterNodes)
			if err != nil {
				log.Error("[verifyTC] Error while verfying TC message signatures", "timeoutCert.Round", timeoutCert.Round, "timeoutCert.GapNumber", timeoutCert.GapNumber, "Signatures len", len(timeoutCert.Signatures), "Error", err)
				haveError = fmt.Errorf("Error while verfying TC message signatures")
				return
			}
			if !verified {
				log.Warn("[verifyTC] Signature not verified doing TC verification", "timeoutCert.Round", timeoutCert.Round, "timeoutCert.GapNumber", timeoutCert.GapNumber, "Signatures len", len(timeoutCert.Signatures))
				haveError = fmt.Errorf("Fail to verify TC due to signature mis-match")
				return
			}
		}(signature)
	}
	wg.Wait()
	if haveError != nil {
		return haveError
	}
	return nil
}

/*
	1. Update highestTC
	2. Check TC round >= node's currentRound. If yes, call setNewRound
*/
func (x *XDPoS_v2) processTC(blockChainReader consensus.ChainReader, timeoutCert *utils.TimeoutCert) error {
	if timeoutCert.Round > x.highestTimeoutCert.Round {
		x.highestTimeoutCert = timeoutCert
	}
	if timeoutCert.Round >= x.currentRound {
		err := x.setNewRound(blockChainReader, timeoutCert.Round+1)
		if err != nil {
			return err
		}
	}
	return nil
}

// Generate and send timeout into BFT channel.
/*
	1. timeout.round = currentRound
	2. Sign the signature
	3. send to broadcast channel
*/
func (x *XDPoS_v2) sendTimeout(chain consensus.ChainReader) error {
	// Construct the gapNumber
	var gapNumber uint64
	currentBlockHeader := chain.CurrentHeader()
	isEpochSwitch, epochNum, err := x.isEpochSwitchAtRound(x.currentRound, currentBlockHeader)
	if err != nil {
		log.Error("[sendTimeout] Error while checking if the currentBlock is epoch switch", "currentRound", x.currentRound, "currentBlockNum", currentBlockHeader.Number, "currentBlockHash", currentBlockHeader.Hash(), "epochNum", epochNum)
		return err
	}

	if isEpochSwitch {
		// Notice this +1 is because we expect a block whos is the child of currentHeader
		currentNumber := currentBlockHeader.Number.Uint64() + 1
		gapNumber = currentNumber - currentNumber%x.config.Epoch - x.config.Gap
		log.Debug("[sendTimeout] is epoch switch when sending out timeout message", "currentNumber", currentNumber, "gapNumber", gapNumber)
	} else {
		epochSwitchInfo, err := x.getEpochSwitchInfo(chain, currentBlockHeader, currentBlockHeader.Hash())
		if err != nil {
			log.Error("[sendTimeout] Error when trying to get current epoch switch info for a non-epoch block", "currentRound", x.currentRound, "currentBlockNum", currentBlockHeader.Number, "currentBlockHash", currentBlockHeader.Hash(), "epochNum", epochNum)
		}
		gapNumber = epochSwitchInfo.EpochSwitchBlockInfo.Number.Uint64() - epochSwitchInfo.EpochSwitchBlockInfo.Number.Uint64()%x.config.Epoch - x.config.Gap
		log.Debug("[sendTimeout] non-epoch-switch block found its epoch block and calculated the gapNumber", "epochSwitchInfo.EpochSwitchBlockInfo.Number", epochSwitchInfo.EpochSwitchBlockInfo.Number.Uint64(), "gapNumber", gapNumber)
	}

	signedHash, err := x.signSignature(utils.TimeoutSigHash(&utils.TimeoutForSign{
		Round:     x.currentRound,
		GapNumber: gapNumber,
	}))
	if err != nil {
		log.Error("[sendTimeout] signSignature when sending out TC", "Error", err)
		return err
	}
	timeoutMsg := &utils.Timeout{
		Round:     x.currentRound,
		Signature: signedHash,
		GapNumber: gapNumber,
	}
	log.Info("[sendTimeout] Timeout message generated, ready to send!", "timeoutMsgRound", timeoutMsg.Round, "timeoutMsgGapNumber", timeoutMsg.GapNumber)
	err = x.timeoutHandler(chain, timeoutMsg)
	if err != nil {
		log.Error("TimeoutHandler error", "TimeoutRound", timeoutMsg.Round, "Error", err)
		return err
	}
	x.broadcastToBftChannel(timeoutMsg)
	return nil
}

/*
	Function that will be called by timer when countdown reaches its threshold.
	In the engine v2, we would need to broadcast timeout messages to other peers
*/
func (x *XDPoS_v2) OnCountdownTimeout(time time.Time, chain interface{}) error {
	x.lock.Lock()
	defer x.lock.Unlock()

	// Check if we are within the master node list
	err := x.allowedToSend(chain.(consensus.ChainReader), chain.(consensus.ChainReader).CurrentHeader(), "timeout")
	if err != nil {
		return err
	}

	err = x.sendTimeout(chain.(consensus.ChainReader))
	if err != nil {
		log.Error("Error while sending out timeout message at time: ", time)
		return err
	}

	x.timeoutCount++
	if x.timeoutCount%x.config.V2.TimeoutSyncThreshold == 0 {
		log.Info("[OnCountdownTimeout] timeout sync threadhold reached, send syncInfo message")
		syncInfo := x.getSyncInfo()
		x.broadcastToBftChannel(syncInfo)
	}

	return nil
}

func (x *XDPoS_v2) hygieneTimeoutPool() {
	x.lock.RLock()
	currentRound := x.currentRound
	x.lock.RUnlock()
	timeoutPoolKeys := x.timeoutPool.PoolObjKeysList()

	// Extract round number
	for _, k := range timeoutPoolKeys {
		keyedRound, err := strconv.ParseInt(strings.Split(k, ":")[0], 10, 64)
		if err != nil {
			log.Error("[hygieneTimeoutPool] Error while trying to get keyedRound inside pool", "Error", err)
			continue
		}
		// Clean up any timeouts round that is 10 rounds older
		if keyedRound < int64(currentRound)-utils.PoolHygieneRound {
			log.Debug("[hygieneTimeoutPool] Cleaned timeout pool at round", "Round", keyedRound, "CurrentRound", currentRound, "Key", k)
			x.timeoutPool.ClearByPoolKey(k)
		}
	}
}
