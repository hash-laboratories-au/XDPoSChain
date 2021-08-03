// Copyright 2014 The go-ethereum Authors
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

package core_test

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/XDPoS"
	"github.com/ethereum/go-ethereum/contracts/validator"
	"github.com/ethereum/go-ethereum/core"
	. "github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

var canonicalSeed = 1

func makeBlockChain(parent *types.Block, n int, engine consensus.Engine, db ethdb.Database, seed int) []*types.Block {
	blocks, _ := GenerateChain(params.TestChainConfig, parent, engine, db, n, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: byte(seed), 19: byte(i)})
	})
	return blocks
}

var (
	acc1Key, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	acc2Key, _ = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	acc3Key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	acc4Key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee04aefe388d1e14474d32c45c72ce7b7a")
	acc1Addr   = crypto.PubkeyToAddress(acc1Key.PublicKey)
	acc2Addr   = crypto.PubkeyToAddress(acc2Key.PublicKey)
	acc3Addr   = crypto.PubkeyToAddress(acc3Key.PublicKey)
	acc4Addr   = crypto.PubkeyToAddress(acc4Key.PublicKey)
	chainID    = int64(1337)
)

func getCommonBackend(t *testing.T) *backends.SimulatedBackend {

	fmt.Println("acc1Addr", acc1Addr.Hash().Hex())
	fmt.Println("acc2Addr", acc2Addr.Hash().Hex())
	fmt.Println("acc3Addr", acc3Addr.Hash().Hex())
	fmt.Println("acc4Addr", acc4Addr.Hash().Hex())

	contractBackend := backends.NewSimulatedBackend(core.GenesisAlloc{
		acc1Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		acc2Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		acc4Addr: {Balance: new(big.Int).SetUint64(10000000000)},
	})
	contractBackend.Commit()

	transactOpts := bind.NewKeyedTransactor(acc1Key)
	validatorCap := new(big.Int)
	validatorCap.SetString("50000000000000000000000", 10)
	validatorAddr, _, err := validator.DeployValidator(transactOpts, contractBackend, []common.Address{acc3Addr}, []*big.Int{validatorCap}, acc3Addr)
	if err != nil {
		t.Fatalf("can't deploy root registry: %v", err)
	}
	contractBackend.Commit()
	/*
		// validatorAddr, _, baseValidator, err := contract.DeployXDCValidator(transactOpts, contractBackend, big.NewInt(50000), big.NewInt(99), big.NewInt(100), big.NewInt(100))
		validatorCap := new(big.Int)
		validatorCap.SetString("10000000000000000000000", 10)
		validatorAddr, _, baseValidator, err := contractValidator.DeployXDCValidator(
			transactOpts,
			contractBackend,
			[]common.Address{acc1Addr, acc3Addr},
			[]*big.Int{validatorCap, validatorCap},
			acc3Addr,
			big.NewInt(50000),
			big.NewInt(1),
			big.NewInt(99),
			big.NewInt(100),
			big.NewInt(100),
		)
		contractBackend.Commit()
	*/

	opts := bind.NewKeyedTransactor(acc4Key)
	opts.Value = new(big.Int).SetUint64(10000)
	acc4Validator, _ := validator.NewValidator(opts, validatorAddr, contractBackend)
	acc4Validator.Propose(acc3Addr)

	contractBackend.Commit()

	return contractBackend

}

func insertBlock(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, t *testing.T) *types.Block {
	block := createXDPoSTestBlock(parentBlock.Hash().Hex(),
		blockCoinBase, 105, blockNum, blockNum, nil,
	)
	err := blockchain.InsertBlock(block)
	if err != nil {
		t.Fatalf("%v at %d", err, blockNum)
	}
	return block
}

func insertBlockTxs(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, txs []*types.Transaction, t *testing.T) *types.Block {
	block := createXDPoSTestBlock(parentBlock.Hash().Hex(),
		blockCoinBase, 105, blockNum, blockNum, txs,
	)
	err := blockchain.InsertBlock(block)
	if err != nil {
		t.Fatalf("%v at %d", err, blockNum)
	}
	return block
}

/*
"transactions": [
	{
	"blockHash": "0xf1a8fce4768c568ea563746a93b7b04c1c676ccad5d1e7d5863456526df51b79",
	"blockNumber": "0x1a0ad0a",
	"from": "xdcd76c962ae085a41d564f6cb38ba5ced1cf7ad1ab",
	"gas": "0x1e8480", // 2000000
	"gasPrice": "0x9c4", // 2500
	"hash": "0x43c477983d199281db09fd8cc71dab2ab7bccfe303329ea524b3c9b665785c2a",
	"input": "0x01267951000000000000000000000000e0996d66a4b2b09dcb1ccfa9fd928c00c13ad0f2",
	"nonce": "0x1",
	"to": "xdc0000000000000000000000000000000000000088",
	"transactionIndex": "0x0",
	"value": "0x84595161401484a000000",
	"v": "0x1c",
	"r": "0xfa3d940ada2c86725c1df90f96f372f9550a4c0055858c0819bd62fd7da54124",
	"s": "0x17e8a7eb1babc506ecd0597ff31d813cba6bd70eafcde3a9adbb46cff4946317"
	}
],

*/
func proposeTX(t *testing.T) *types.Transaction {
	data := []byte("0x01267951000000000000000000000000e0996d66a4b2b09dcb1ccfa9fd928c00c13ad0f2")
	gasPrice := big.NewInt(int64(2500))
	gasLimit := uint64(2000000)
	amountInt, _ := strconv.ParseInt("10000000000000000000000824", 10, 64)
	amount := big.NewInt(amountInt)
	nonce := uint64(0x0)
	to := common.HexToAddress("0x43c477983d199281db09fd8cc71dab2ab7bccfe303329ea524b3c9b665785c2a")
	tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)

	signedTX, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(chainID)), acc4Key)
	if err != nil {
		t.Fatal(err)
	}
	return signedTX
}
func TestPropose(t *testing.T) {
	_, blockchain, _ := newXDPoSCanonical(0)
	backend := getCommonBackend(t)
	blockchain.Client = backend
	block := blockchain.Genesis()
	for i := 1; i < 10; i++ {
		blockCoinBase := fmt.Sprintf("0x1110000000000000000000000000000000000%3d", i)
		b := insertBlock(blockchain, i, blockCoinBase, block, t)
		block = b
	}
	t.Logf("Inserting block with propose at 10...")
	block10CoinBase := "0x2220000000000000000000000000000000000010"
	tx := proposeTX(t)
	insertBlockTxs(blockchain, 10, block10CoinBase, block, []*types.Transaction{tx}, t)
	if blockchain.GetBlockByNumber(10).Header().Coinbase.Hex() == fmt.Sprintf("0x1110000000000000000000000000000000000010") {
		t.Fatalf("Canonical chain 10 should keep the old 450 block, new insert should remain as uncle")
	}

}

func TestUpdateM1(t *testing.T) {
	_, blockchain, _ := newXDPoSCanonical(0)
	backend := getCommonBackend(t)
	blockchain.Client = backend

	block := blockchain.Genesis()
	t.Logf("Inserting 450 blocks...")
	for i := 1; i <= 450; i++ {
		blockCoinBase := fmt.Sprintf("0x1110000000000000000000000000000000000%3d", i)
		b := insertBlock(blockchain, i, blockCoinBase, block, t)
		block = b

	}
	t.Logf("Inserting a longer chain forking at 450...")
	block449 := blockchain.GetBlockByNumber(449)

	block450CoinBase := "0x2220000000000000000000000000000000000450"
	block450 := insertBlock(blockchain, 450, block450CoinBase, block449, t)

	if blockchain.GetBlockByNumber(450).Header().Coinbase.Hex() == fmt.Sprintf("0x1110000000000000000000000000000000000450") {
		t.Fatalf("Canonical chain 450 should keep the old 450 block, new insert should remain as uncle")
	}

	block451CoinBase := "0x2220000000000000000000000000000000000451"

	insertBlock(blockchain, 451, block451CoinBase, block450, t)

	if blockchain.GetBlockByNumber(450).Header().Coinbase.Hex() != "xdc2220000000000000000000000000000000000450" {
		t.Fatalf("block chain should update to new block based on longest chain theory")
	}
	if blockchain.GetBlockByNumber(451).Header().Coinbase.Hex() != "xdc2220000000000000000000000000000000000451" {
		t.Fatalf("block chain should update to new block based on longest chain theory %s", blockchain.GetBlockByNumber(451).Header().Coinbase.Hex())
	}
}

func createXDPoSTestBlock(ParentHash, Coinbase string, Difficulty, Number, Time int, txs []*types.Transaction) *types.Block {
	extraSubstring := "d7830100018358444388676f312e31342e31856c696e75780000000000000000b185dc0d0e917d18e5dbf0746be6597d3331dd27ea0554e6db433feb2e81730b20b2807d33a1527bf43cd3bc057aa7f641609c2551ebe2fd575f4db704fbf38101"
	UncleHash := "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
	TxHash := "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
	ReceiptHash := "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
	Root := "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"

	extraByte, _ := hex.DecodeString(extraSubstring)
	header := types.Header{
		ParentHash:  common.HexToHash(ParentHash),
		UncleHash:   common.HexToHash(UncleHash),
		TxHash:      common.HexToHash(TxHash),
		ReceiptHash: common.HexToHash(ReceiptHash),
		Root:        common.HexToHash(Root),
		Coinbase:    common.HexToAddress(Coinbase),
		Difficulty:  big.NewInt(int64(Difficulty)),
		Number:      big.NewInt(int64(Number)),
		GasLimit:    21000,
		Time:        big.NewInt(int64(Time)),
		Extra:       extraByte,
	}
	var block *types.Block
	if len(txs) == 0 {
		block = types.NewBlockWithHeader(&header)
	} else {
		block = types.NewBlock(&header, txs, nil, nil)
	}
	return block
}

// newXDPoSCanonical creates a chain database, and injects a deterministic canonical
// chain. Depending on the full flag, if creates either a full block chain or a
// header only chain.
func newXDPoSCanonical(n int) (ethdb.Database, *BlockChain, error) {
	// Initialize a fresh chain with only a genesis block
	gspec := new(Genesis)
	// change genesis fields
	extraByte, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000001b82c4bf317fcafe3d77e8b444c82715d216afe845b7bd987fa22c9bac89b71f0ded03f6e150ba31ad670b2b166684657ffff95f4810380ae7381e9bce41231d5dd8cdd7499e418b648c00af75d184a2f9aba09a6fa4a46fb1a6a3919b027d9cac5aa6890000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	gspec.ExtraData = extraByte
	gspec.Difficulty = big.NewInt(105)
	db, _ := ethdb.NewMemDatabase()
	genesis := gspec.MustCommit(db)

	XDPoSConfig := params.XDPoSConfig{
		Period:              2,
		Epoch:               900,
		Reward:              250,
		RewardCheckpoint:    900,
		Gap:                 450,
		FoudationWalletAddr: common.HexToAddress("0x0000000000000000000000000000000000000068"),
	}
	engine := XDPoS.New(&XDPoSConfig, db)
	config := &params.ChainConfig{big.NewInt(chainID), big.NewInt(0), nil, false, big.NewInt(0), common.Hash{}, big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, nil, &XDPoSConfig}
	blockchain, _ := NewBlockChain(db, nil, config, engine, vm.Config{})
	// Create and inject the requested chain
	if n == 0 {
		return db, blockchain, nil
	}
	// Full block-chain requested
	blocks := makeBlockChain(genesis, n, engine, db, canonicalSeed)
	_, err := blockchain.InsertChain(blocks)
	return db, blockchain, err
}
