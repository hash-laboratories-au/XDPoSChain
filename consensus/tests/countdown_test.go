package tests

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestCountdownTimeoutToSendTimeoutMessage(t *testing.T) {
	blockchain, _, _, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 2251, params.TestXDPoSMockChainConfig, 0)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	timeoutMsg := <-engineV2.BroadcastCh
	poolSize := engineV2.GetTimeoutPoolSize(timeoutMsg.(*utils.Timeout))
	assert.Equal(t, poolSize, 1)
	assert.NotNil(t, timeoutMsg)
	assert.Equal(t, uint64(1350), timeoutMsg.(*utils.Timeout).GapNumber)
	assert.Equal(t, utils.Round(1), timeoutMsg.(*utils.Timeout).Round)

	valid, err := engineV2.VerifyTimeoutMessage(blockchain, timeoutMsg.(*utils.Timeout))
	assert.Nil(t, err)
	assert.True(t, valid)
}
