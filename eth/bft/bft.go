package bft

import (
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/engines/engine_v2"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
)

type collectVoteFn func(utils.Vote) error
type collectTimeoutFn func(utils.Timeout) error
type updateRoundFn func(utils.Timeout) error
type VerifyBlockInfoFn func(header *types.Header) error
type VerifySyncInfoMessageFn func(utils.SyncInfo) error
type VerifyVoteFn func(utils.Vote) error
type VerifyTimeoutMessageFn func(utils.Timeout) error
type broadcastVoteFn func(utils.Vote)
type broadcastTimeoutFn func(utils.Timeout)
type broadcastSyncInfoFn func(utils.SyncInfo)

type BFT struct {
	broadcastCh chan interface{}
	quit        chan struct{}
	consensus   ConsensusFns
	broadcast   BroadcastFns
}

type ConsensusFns struct {
	verifySyncInfo  VerifySyncInfoMessageFn
	verifyVote      VerifyVoteFn
	verifyTimeout   VerifyTimeoutMessageFn
	verifyBlockInfo VerifyBlockInfoFn
}

type BroadcastFns struct {
	Vote     broadcastVoteFn
	Timeout  broadcastTimeoutFn
	SyncInfo broadcastSyncInfoFn
}

func New(engine *engine_v2.XDPoS_v2, broadcasts BroadcastFns) *BFT {
	consensus := ConsensusFns{
		verifySyncInfo:  engine.VerifySyncInfoMessage,
		verifyVote:      engine.VerifyVoteMessage,
		verifyTimeout:   engine.VerifyTimeoutMessage,
		verifyBlockInfo: engine.VerifyBlockInfo,
	}
	return &BFT{
		broadcastCh: engine.BroadcastCh,
		consensus:   consensus,
		broadcast:   broadcasts,
	}
}

func (b *BFT) Vote(vote utils.Vote) {
	log.Trace("Receive Vote", "vote", vote)
	err := b.consensus.verifyVote(vote)
	if err != nil {
		log.Error("Collect BFT Vote", "error", err)
		return
	}
	b.broadcast.Vote(vote)
}

func (b *BFT) Timeout(timeout utils.Timeout) {
	log.Trace("Receive Timeout", "timeout", timeout)

	err := b.consensus.verifyTimeout(timeout)
	if err != nil {
		log.Error("Collect BFT Timeout", "error", err)
		return
	}
	b.broadcast.Timeout(timeout)
}

func (b *BFT) SyncInfo(syncInfo utils.SyncInfo) {
	log.Trace("Receive SyncInfo", "syncInfo", syncInfo)
	err := b.consensus.verifySyncInfo(syncInfo)
	if err != nil {
		log.Error("Collect BFT SyncInfo", "error", err)
		return
	}
	b.broadcast.SyncInfo(syncInfo)
}
func (b *BFT) Start() {
	go b.loop()
}

func (b *BFT) Stop() {
	close(b.quit)
}

func (b *BFT) loop() {

	for {
		select {
		case <-b.quit:
			return
		case obj := <-b.broadcastCh:
			switch v := obj.(type) {
			case utils.Vote:
				b.broadcast.Vote(v)
			case utils.Timeout:
				b.broadcast.Timeout(v)
			case utils.SyncInfo:
				b.broadcast.SyncInfo(v)
			default:

			}
		}
	}
}
