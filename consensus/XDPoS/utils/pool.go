package utils

import (
	"github.com/XinFinOrg/XDPoSChain/common"
)

type PoolObj interface {
	Hash() common.Hash
	PoolKey() string
}
type Pool struct {
	objList       map[string]map[common.Hash]PoolObj
	threshold     int
	OnThresholdFn func([]PoolObj) error
}

func NewPool(threshold int) *Pool {
	return &Pool{
		objList:   make(map[string]map[common.Hash]PoolObj),
		threshold: threshold,
	}
}

func (p *Pool) Add(obj PoolObj) error {
	objListKeyed, ok := p.objList[obj.PoolKey()]
	if !ok {
		p.objList[obj.PoolKey()] = make(map[common.Hash]PoolObj)
		objListKeyed = p.objList[obj.PoolKey()]
	}
	objListKeyed[obj.Hash()] = obj
	if len(objListKeyed) >= p.threshold && p.OnThresholdFn != nil {
		objs := make([]PoolObj, p.threshold)
		i := 0
		for _, t := range objListKeyed {
			objs[i] = t
			i += 1
			if i == p.threshold {
				break
			}
		}
		p.Clear()
		return p.OnThresholdFn(objs)
	} else {
		return nil
	}
}

func (p *Pool) Clear() {
	p.objList = make(map[string]map[common.Hash]PoolObj)
}

func (p *Pool) SetThreshold(t int) {
	p.threshold = t
}
