// Copyright 2014 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//

// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/XinFinOrg/XDPoSChain/cmd/utils"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
)

func main() {
	// Make sure we have a valid genesis JSON
	genesisPath := os.Args[1]
	if !strings.Contains(genesisPath, ".json") {
		utils.Fatalf("Must supply path to genesis JSON file, %s", genesisPath)
	}
	file, err := os.Open(genesisPath)
	if err != nil {
		utils.Fatalf("Failed to read genesis file: %v", err)
	}
	defer file.Close()

	genesis := new(core.Genesis)
	if err := json.NewDecoder(file).Decode(genesis); err != nil {
		utils.Fatalf("invalid genesis file: %v", err)
	}
	database := rawdb.NewMemoryDatabase()
	genesisBlock := genesis.MustCommit(database)
	if genesisBlock == nil {
		utils.Fatalf("nil genesis block")
	}
	statedb, err := state.New(genesisBlock.Root(), state.NewDatabase(database))
	if err != nil {
		utils.Fatalf("Failed to create state: %v", err)
	}
	candidates := state.GetCandidates(statedb)
	for i, c := range candidates {
		fmt.Printf("candidates %d: %s\n", i, c.Hex())
		fmt.Printf("\towner: %s, cap: %d\n", state.GetCandidateOwner(statedb, c).Hex(), state.GetCandidateCap(statedb, c).Uint64())
		voters := state.GetVoters(statedb, c)
		fmt.Println("voter 0 should be the same as owner")
		for j, v := range voters {
			fmt.Printf("\tvoter %d: %s, cap: %d\n", j, v.Hex(), state.GetVoterCap(statedb, c, v).Uint64())
		}
	}
}
