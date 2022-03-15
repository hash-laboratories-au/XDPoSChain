package engine_v2

import (
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
)

/*
	Testing tools
*/

func (x *XDPoS_v2) SetNewRoundFaker(blockChainReader consensus.ChainReader, newRound utils.Round, resetTimer bool) {
	x.lock.Lock()
	defer x.lock.Unlock()
	// Reset a bunch of things
	if resetTimer {
		x.timeoutWorker.Reset(blockChainReader)
	}
	x.currentRound = newRound
}

// for test only
func (x *XDPoS_v2) ProcessQCFaker(chain consensus.ChainReader, qc *utils.QuorumCert) error {
	x.lock.Lock()
	defer x.lock.Unlock()
	return x.processQC(chain, qc)
}

// Utils for test to check currentRound value
func (x *XDPoS_v2) GetCurrentRoundFaker() utils.Round {
	x.lock.RLock()
	defer x.lock.RUnlock()
	return x.currentRound
}

// Utils for test to get current Pool size
func (x *XDPoS_v2) GetVotePoolSizeFaker(vote *utils.Vote) int {
	return x.votePool.Size(vote)
}

// Utils for test to get Timeout Pool Size
func (x *XDPoS_v2) GetTimeoutPoolSizeFaker(timeout *utils.Timeout) int {
	return x.timeoutPool.Size(timeout)
}

// WARN: This function is designed for testing purpose only!
// Utils for test to check currentRound values
func (x *XDPoS_v2) GetPropertiesFaker() (utils.Round, *utils.QuorumCert, *utils.QuorumCert, *utils.TimeoutCert, utils.Round, *utils.BlockInfo) {
	x.lock.RLock()
	defer x.lock.RUnlock()
	return x.currentRound, x.lockQuorumCert, x.highestQuorumCert, x.highestTimeoutCert, x.highestVotedRound, x.highestCommitBlock
}

// WARN: This function is designed for testing purpose only!
// Utils for tests to set engine specific values
func (x *XDPoS_v2) SetPropertiesFaker(highestQC *utils.QuorumCert, highestTC *utils.TimeoutCert) {
	x.highestQuorumCert = highestQC
	x.highestTimeoutCert = highestTC
}