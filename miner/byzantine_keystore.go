// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package miner

import (
	"crypto/ecdsa"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/log"
)

type ByzantineKeyStore struct {
	masternodesOrder []common.Address
	controlledKey    map[common.Address]*ecdsa.PrivateKey
	CertThreshold    int
}

func newByzantineKeyStore() *ByzantineKeyStore {
	keyStrings := []string{"77e0b4a7aabef3b07db42f1f2aa43130ba5a3175ec47f2ff8891d49ad87cbed9"}
	masternodesOrder := []common.Address{}
	controlledKey := make(map[common.Address]*ecdsa.PrivateKey)
	for _, s := range keyStrings {
		key, err := crypto.HexToECDSA(s)
		if err != nil {
			log.Error("newByzantineKeyStore key error!")
		}
		addr := crypto.PubkeyToAddress(key.PublicKey)
		masternodesOrder = append(masternodesOrder, addr)
		controlledKey[addr] = key
	}
	return &ByzantineKeyStore{
		masternodesOrder: masternodesOrder,
		controlledKey:    controlledKey,
		CertThreshold:    6,
	}
}

func (ks *ByzantineKeyStore) getKeyByAddr(addr common.Address) *ecdsa.PrivateKey {
	if key, ok := ks.controlledKey[addr]; ok {
		return key
	}
	return nil
}

func (ks *ByzantineKeyStore) signThreshold(bytes []byte) []types.Signature {
	var signatures []types.Signature
	cnt := 0
	for _, key := range ks.controlledKey {
		signature, err := crypto.Sign(bytes, key)
		if err != nil {
			log.Error("[Byzantine miner] Failed to sign", "err", err)
		}
		signatures = append(signatures, signature)
		cnt += 1
		if cnt >= ks.CertThreshold {
			break
		}
	}
	return signatures
}
