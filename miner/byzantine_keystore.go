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
	keyStrings := []string{
		"77e0b4a7aabef3b07db42f1f2aa43130ba5a3175ec47f2ff8891d49ad87cbed9",
		"31b0fbcba7b60ea9974ae1bac0523af8cd72661de47ea2d3569344c975b93801",
		"5a3457e9323ef7f9351d7b6d8f4d5c2c7c66a5e094142d6e186c86402b29a787",
		"363f48b205f95859e13ea1acf6b047631ab34e69d193bbf5eb0df871decca69e",
		"bde24b587c04ab8d8cc2acc176a4b85e646d3c89f4d98d570629d756aea68303",
		"3efdb44088929167487da052125162b48d8d54fe8f7b7db11b5d5cc3b9a1c14b",
		"1c40ebf394c9c9db15f60528f6a030ba9f465a7c615acd9b9d79792175b6bcd6",
		"58fbe847ab6faa2fb5559b4d1f1e02573e222d2524b6f4598a301897c0881e71",
		"64651f33879becd32391e3cf802680f3621500c55fb53db7b6b041ff74c3a62f",
		"e754b95280b2232ffb4398de0cdda06c2be24ef8aa5c6aba090802e0cd706022",
	}
	masternodesOrder := []common.Address{}
	controlledKey := make(map[common.Address]*ecdsa.PrivateKey)
	for i, s := range keyStrings {
		key, err := crypto.HexToECDSA(s)
		if err != nil {
			log.Error("newByzantineKeyStore key error!")
		}
		addr := crypto.PubkeyToAddress(key.PublicKey)
		masternodesOrder = append(masternodesOrder, addr)
		controlledKey[addr] = key
		log.Info("Byzantine controls %d addr: %s\n", i, addr.Hex())
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

func (ks *ByzantineKeyStore) getAddrIndex(addr common.Address) (int, bool) {
	for i, a := range ks.masternodesOrder {
		if a == addr {
			return i, true
		}
	}
	return 0, false
}

func (ks *ByzantineKeyStore) getAddrByIndex(i int) common.Address {
	return ks.masternodesOrder[i]
}

func (ks *ByzantineKeyStore) signThreshold(bytes []byte) []types.Signature {
	var signatures []types.Signature
	cnt := 0
	for _, addr := range ks.masternodesOrder {
		key := ks.controlledKey[addr]
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

func (ks *ByzantineKeyStore) reorderByMasternodes(mn []common.Address) {
	for _, addr := range mn {
		if _, ok := ks.controlledKey[addr]; !ok {
			log.Error("[Byzantine miner] found a key Byzantine does not control", "addr", addr.Hex())
			return
		}
	}
	mn_copy := make([]common.Address, len(mn))
	copy(mn_copy, mn)
	ks.masternodesOrder = mn_copy
}
