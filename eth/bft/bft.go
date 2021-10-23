package bft

import (
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/log"
)

type collectVoteFn func(utils.VoteType) error

type collectTimeoutFn func(utils.TimeoutType) error

type updateRoundFn func(utils.SyncInfoType) error

type broadcastVoteFn func(utils.VoteType)

type broadcastTimeoutFn func(utils.TimeoutType)

type broadcastSyncInfoFn func(utils.SyncInfoType)

type BFT struct {
	broadcastCh chan interface{}
	quit        chan struct{}
	engine      ConsensusFns
	broadcast   BroadcastFns
}

type ConsensusFns struct {
	collectVote    collectVoteFn
	collectTimeout collectTimeoutFn
	updateRound    updateRoundFn
}

type BroadcastFns struct {
	Vote     broadcastVoteFn
	Timeout  broadcastTimeoutFn
	SyncInfo broadcastSyncInfoFn
}

func New(engine *XDPoS.XDPoS, broadcasts BroadcastFns) *BFT {
	consensus := ConsensusFns{
		collectVote:    engine.CollectVote,
		collectTimeout: engine.CollectTimeout,
		updateRound:    engine.UpdateRound,
	}
	return &BFT{
		broadcastCh: engine.EngineV2.BroadcastCh,
		engine:      consensus,
		broadcast:   broadcasts,
	}
}

func (b *BFT) Vote(vote interface{}) {
	log.Trace("Receive Vote", "vote", vote)
	err := b.engine.collectVote(vote)
	if err != nil {
		log.Error("Collect BFT Vote", "error", err)
		return
	}
	b.broadcast.Vote(vote)
}

func (b *BFT) Timeout(timeout interface{}) {
	log.Trace("Receive Timeout", "timeout", timeout)

	err := b.engine.collectTimeout(timeout)
	if err != nil {
		log.Error("Collect BFT Timeout", "error", err)
		return
	}
	b.broadcast.Timeout(timeout)
}

func (b *BFT) SyncInfo(syncInfo interface{}) {
	log.Trace("Receive SyncInfo", "syncInfo", syncInfo)
	err := b.engine.updateRound(syncInfo)
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
			case utils.VoteType:
				b.broadcast.Vote(v)
			case utils.TimeoutType:
				b.broadcast.Timeout(v)
			case utils.SyncInfoType:
				b.broadcast.SyncInfo(v)
			default:

			}
		}
	}
}
