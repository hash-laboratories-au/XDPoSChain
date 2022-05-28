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
	"fmt"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

func TestKeys(t *testing.T) {
	newByzantineKeyStore()
}

func TestSignThreshold(t *testing.T) {
	ks := newByzantineKeyStore()
	hash := common.Hex2Bytes("c8a9dd37f7c5e2e1545a149a94e6a23f9aca91ac18e88c0ea72d2dcd145fd87f")
	s := ks.signThreshold(hash)
	fmt.Printf("%v\n", s)
}
