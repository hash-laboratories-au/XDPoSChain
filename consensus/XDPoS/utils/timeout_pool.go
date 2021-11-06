package utils

import "github.com/XinFinOrg/XDPoSChain/common"

type TimeoutPool struct {
	hashToTimeout map[common.Hash]*Timeout
	currentRound  Round
	certSize      int
}

func NewTimeoutPool(certSize int) *TimeoutPool {
	return &TimeoutPool{hashToTimeout: make(map[common.Hash]*Timeout), currentRound: 0, certSize: certSize}
}

func (pool *TimeoutPool) AddTimeout(timeout *Timeout) *TimeoutCert {
	if timeout.Round != pool.currentRound {
		return nil
	}
	pool.hashToTimeout[timeout.Hash()] = timeout
	if len(pool.hashToTimeout) >= pool.certSize {
		signatures := [][]byte{}
		for h, t := range pool.hashToTimeout {
			signatures = append(signatures, t.Signature)
			delete(pool.hashToTimeout, h)
			if len(signatures) == pool.certSize {
				break
			}
		}
		return &TimeoutCert{Round: timeout.Round, Signatures: signatures}
	} else {
		return nil
	}
}

func (pool *TimeoutPool) SetNewRound(round Round) {
	pool.currentRound = round
	pool.hashToTimeout = make(map[common.Hash]*Timeout) //TODO: is this corrent way to clear it?
}
