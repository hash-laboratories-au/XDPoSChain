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

func NewPool(certSize int) *Pool {
	return &Pool{
		objList:   make(map[string]map[common.Hash]PoolObj),
		threshold: certSize,
	}
}

func (pool *Pool) Add(obj PoolObj) error {
	objListKeyed, ok := pool.objList[obj.PoolKey()]
	if !ok {
		pool.objList[obj.PoolKey()] = make(map[common.Hash]PoolObj)
		objListKeyed = pool.objList[obj.PoolKey()]
	}
	objListKeyed[obj.Hash()] = obj
	if len(objListKeyed) >= pool.threshold && pool.OnThresholdFn != nil {
		objs := make([]PoolObj, pool.threshold)
		i := 0
		for _, t := range objListKeyed {
			objs[i] = t
			i += 1
			if i == pool.threshold {
				break
			}
		}
		pool.Clear()
		return pool.OnThresholdFn(objs)
	} else {
		return nil
	}
}

func (pool *Pool) Clear() {
	pool.objList = make(map[string]map[common.Hash]PoolObj)
}

func (pool *Pool) SetThreshold(t int) {
	pool.threshold = t
}
