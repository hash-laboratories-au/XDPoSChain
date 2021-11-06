package consensus

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestCountdownTimeoutToSendTimeoutMessage(t *testing.T) {
	blockchain, _, _, _ := PrepareXDCTestBlockChain(t, 11, params.TestXDPoSMockChainConfigWithV2Engine)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	engineV2.SetNewRoundFaker(utils.Round(1))

	timeoutMsg := <-engineV2.BroadcastCh
	assert.NotNil(t, timeoutMsg)

	valid, err := engineV2.VerifyTimeoutMessage(*timeoutMsg.(*utils.Timeout))
	// We can only test valid = false for now as the implementation for getCurrentRoundMasterNodes is not complete
	assert.False(t, valid)
	// This shows we are able to decode the timeout message, which is what this test is all about
	assert.Regexp(t, "^Masternodes does not contain signer addres.*", err.Error())
}
