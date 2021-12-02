package tests

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestCountdownTimeoutToSendTimeoutMessage(t *testing.T) {
	blockchain, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 11, params.TestXDPoSMockChainConfigWithV2Engine)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	engineV2.SetNewRoundFaker(utils.Round(1), true)

	timeoutMsg := <-engineV2.BroadcastCh
	assert.NotNil(t, timeoutMsg)

	valid, err := engineV2.VerifyTimeoutMessage(timeoutMsg.(*utils.Timeout))
	// We can only test valid = false for now as the implementation for getCurrentRoundMasterNodes is not complete
	assert.False(t, valid)
	// This shows we are able to decode the timeout message, which is what this test is all about
	assert.Regexp(t, "^Masternodes does not contain signer addres.*", err.Error())
}

// Timeout handler
func TestTimeoutMessageHandlerSuccessfullyGenerateTCandSyncInfo(t *testing.T) {
	blockchain, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 11, params.TestXDPoSMockChainConfigWithV2Engine)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Set round to 1
	engineV2.SetNewRoundFaker(utils.Round(1), false)
	// Create two timeout message which will not reach timeout pool threshold
	timeoutMsg := &utils.Timeout{
		Round:     utils.Round(1),
		Signature: []byte{1},
	}

	err := engineV2.TimeoutHandler(timeoutMsg)
	assert.Nil(t, err)
	currentRound, _, _ := engineV2.GetProperties()
	assert.Equal(t, utils.Round(1), currentRound)
	timeoutMsg = &utils.Timeout{
		Round:     utils.Round(1),
		Signature: []byte{2},
	}
	err = engineV2.TimeoutHandler(timeoutMsg)
	assert.Nil(t, err)
	currentRound, _, _ = engineV2.GetProperties()
	assert.Equal(t, utils.Round(1), currentRound)
	// Create a timeout message that should trigger timeout pool hook
	timeoutMsg = &utils.Timeout{
		Round:     utils.Round(1),
		Signature: []byte{3},
	}

	err = engineV2.TimeoutHandler(timeoutMsg)
	assert.Nil(t, err)

	syncInfoMsg := <-engineV2.BroadcastCh

	currentRound, _, _ = engineV2.GetProperties()

	assert.NotNil(t, syncInfoMsg)

	// Should have QC, however, we did not inilise it, hence will show default nil value
	qc := syncInfoMsg.(utils.SyncInfo).HighestQuorumCert
	assert.Nil(t, qc)

	tc := syncInfoMsg.(utils.SyncInfo).HighestTimeoutCert
	assert.NotNil(t, tc)
	assert.Equal(t, tc.Round, utils.Round(1))
	sigatures := []utils.Signature{[]byte{1}, []byte{2}, []byte{3}}
	assert.ElementsMatch(t, tc.Signatures, sigatures)
	assert.Equal(t, utils.Round(2), currentRound)
}

func TestThrowErrorIfTimeoutMsgRoundNotEqualToCurrentRound(t *testing.T) {
	blockchain, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 11, params.TestXDPoSMockChainConfigWithV2Engine)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Set round to 3
	engineV2.SetNewRoundFaker(utils.Round(3), false)
	timeoutMsg := &utils.Timeout{
		Round:     utils.Round(2),
		Signature: []byte{1},
	}

	err := engineV2.TimeoutHandler(timeoutMsg)
	assert.NotNil(t, err)
	// Timeout msg round > currentRound
	assert.Equal(t, "Timeout message round number: 2 does not match currentRound: 3", err.Error())

	// Set round to 1
	engineV2.SetNewRoundFaker(utils.Round(1), false)
	err = engineV2.TimeoutHandler(timeoutMsg)
	assert.NotNil(t, err)
	// Timeout msg round < currentRound
	assert.Equal(t, "Timeout message round number: 2 does not match currentRound: 1", err.Error())
}

// VoteHandler
func TestVoteMessageHandlerSuccessfullyGeneratedAndProcessQC(t *testing.T) {
	blockchain, _, currentBlock, _ := PrepareXDCTestBlockChainForV2Engine(t, 11, params.TestXDPoSMockChainConfigWithV2Engine)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// parentBlock := blockchain.GetBlockByHash(currentBlock.ParentHash())
	// grandParentBlock := blockchain.GetBlockByHash(parentBlock.ParentHash())

	blockInfo := &utils.BlockInfo{
		Hash:   currentBlock.Hash(),
		Round:  utils.Round(11),
		Number: big.NewInt(11),
	}

	// Set round to 11
	engineV2.SetNewRoundFaker(utils.Round(11), false)
	// Create two timeout message which will not reach vote pool threshold
	voteMsg := &utils.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         []byte{1},
	}

	err := engineV2.VoteHandler(blockchain, voteMsg)
	assert.Nil(t, err)
	currentRound, lockQuorumCert, highestQuorumCert := engineV2.GetProperties()
	// Inilised with nil and 0 round
	assert.Nil(t, lockQuorumCert)
	assert.Nil(t, highestQuorumCert)
	assert.Equal(t, utils.Round(11), currentRound)
	voteMsg = &utils.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         []byte{2},
	}
	err = engineV2.VoteHandler(blockchain, voteMsg)
	assert.Nil(t, err)
	currentRound, lockQuorumCert, highestQuorumCert = engineV2.GetProperties()
	// Still using the initlised value because we did not yet go to the next round
	assert.Nil(t, lockQuorumCert)
	assert.Nil(t, highestQuorumCert)

	assert.Equal(t, utils.Round(11), currentRound)

	// Create a vote message that should trigger vote pool hook and increment the round to 12
	voteMsg = &utils.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         []byte{3},
	}

	err = engineV2.VoteHandler(blockchain, voteMsg)
	assert.Nil(t, err)
	currentRound, lockQuorumCert, highestQuorumCert = engineV2.GetProperties()
	// The lockQC shall be the parent's QC round number
	assert.Equal(t, utils.Round(11), lockQuorumCert.ProposedBlockInfo.Round)
	// The highestQC proposedBlockInfo shall be the same as the one from its votes
	assert.Equal(t, highestQuorumCert.ProposedBlockInfo, voteMsg.ProposedBlockInfo)
	// Check round has now changed from 11 to 12
	assert.Equal(t, utils.Round(12), currentRound)
}

func TestThrowErrorIfVoteMsgRoundNotEqualToCurrentRound(t *testing.T) {
	blockchain, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 11, params.TestXDPoSMockChainConfigWithV2Engine)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	blockInfo := &utils.BlockInfo{
		Hash:   common.HexToHash("0x1"),
		Round:  utils.Round(12),
		Number: big.NewInt(999),
	}

	// Set round to 13
	engineV2.SetNewRoundFaker(utils.Round(13), false)
	voteMsg := &utils.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         []byte{1},
	}

	// voteRound > currentRound
	err := engineV2.VoteHandler(blockchain, voteMsg)
	assert.NotNil(t, err)
	assert.Equal(t, "Vote message round number: 12 does not match currentRound: 13", err.Error())

	// Set round to 11
	engineV2.SetNewRoundFaker(utils.Round(11), false)
	err = engineV2.VoteHandler(blockchain, voteMsg)
	assert.NotNil(t, err)
	// voteRound < currentRound
	assert.Equal(t, "Vote message round number: 12 does not match currentRound: 11", err.Error())
}

func TestProcessVoteMsgThenTimeoutMsg(t *testing.T) {
	blockchain, _, currentBlock, _ := PrepareXDCTestBlockChainForV2Engine(t, 11, params.TestXDPoSMockChainConfigWithV2Engine)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Set round to 1
	engineV2.SetNewRoundFaker(utils.Round(11), false)

	// Start with vote messages
	blockInfo := &utils.BlockInfo{
		Hash:   currentBlock.Hash(),
		Round:  utils.Round(11),
		Number: big.NewInt(11),
	}
	// Create two vote message which will not reach vote pool threshold
	voteMsg := &utils.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         []byte{1},
	}

	err := engineV2.VoteHandler(blockchain, voteMsg)
	assert.Nil(t, err)
	currentRound, lockQuorumCert, highestQuorumCert := engineV2.GetProperties()
	// Inilised with nil and 0 round
	assert.Nil(t, lockQuorumCert)
	assert.Nil(t, highestQuorumCert)

	assert.Equal(t, utils.Round(11), currentRound)
	voteMsg = &utils.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         []byte{2},
	}
	err = engineV2.VoteHandler(blockchain, voteMsg)
	assert.Nil(t, err)
	currentRound, _, _ = engineV2.GetProperties()
	assert.Equal(t, utils.Round(11), currentRound)

	// Create a vote message that should trigger vote pool hook
	voteMsg = &utils.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         []byte{3},
	}

	err = engineV2.VoteHandler(blockchain, voteMsg)
	assert.Nil(t, err)
	// Check round has now changed from 11 to 12
	currentRound, lockQuorumCert, highestQuorumCert = engineV2.GetProperties()
	// The lockQC shall be the parent's QC round number
	assert.Equal(t, utils.Round(11), lockQuorumCert.ProposedBlockInfo.Round)
	// The highestQC proposedBlockInfo shall be the same as the one from its votes
	assert.Equal(t, highestQuorumCert.ProposedBlockInfo, voteMsg.ProposedBlockInfo)

	assert.Equal(t, utils.Round(12), currentRound)

	// We shall have highestQuorumCert in engine now, let's do timeout msg to see if we can broadcast SyncInfo which contains both highestQuorumCert and HighestTimeoutCert

	// First, all incoming old timeout msg shall not be processed
	timeoutMsg := &utils.Timeout{
		Round:     utils.Round(11),
		Signature: []byte{1},
	}

	err = engineV2.TimeoutHandler(timeoutMsg)
	assert.NotNil(t, err)
	assert.Equal(t, "Timeout message round number: 11 does not match currentRound: 12", err.Error())

	// Ok, let's do the timeout msg which is on the same round as the current round by creating two timeout message which will not reach timeout pool threshold
	timeoutMsg = &utils.Timeout{
		Round:     utils.Round(12),
		Signature: []byte{1},
	}

	err = engineV2.TimeoutHandler(timeoutMsg)
	assert.Nil(t, err)
	currentRound, _, _ = engineV2.GetProperties()
	assert.Equal(t, utils.Round(12), currentRound)
	timeoutMsg = &utils.Timeout{
		Round:     utils.Round(12),
		Signature: []byte{2},
	}
	err = engineV2.TimeoutHandler(timeoutMsg)
	assert.Nil(t, err)
	currentRound, _, _ = engineV2.GetProperties()
	assert.Equal(t, utils.Round(12), currentRound)

	// Create a timeout message that should trigger timeout pool hook
	timeoutMsg = &utils.Timeout{
		Round:     utils.Round(12),
		Signature: []byte{3},
	}

	err = engineV2.TimeoutHandler(timeoutMsg)
	assert.Nil(t, err)

	syncInfoMsg := <-engineV2.BroadcastCh
	assert.NotNil(t, syncInfoMsg)

	// Should have HighestQuorumCert from previous round votes
	qc := syncInfoMsg.(utils.SyncInfo).HighestQuorumCert
	assert.NotNil(t, qc)
	assert.Equal(t, utils.Round(11), qc.ProposedBlockInfo.Round)

	tc := syncInfoMsg.(utils.SyncInfo).HighestTimeoutCert
	assert.NotNil(t, tc)
	assert.Equal(t, utils.Round(12), tc.Round)
	sigatures := []utils.Signature{[]byte{1}, []byte{2}, []byte{3}}
	assert.ElementsMatch(t, tc.Signatures, sigatures)
	// Round shall be +1 now
	currentRound, _, _ = engineV2.GetProperties()
	assert.Equal(t, utils.Round(13), currentRound)
}

func TestBlockPrepareFunction(t *testing.T) {

}
