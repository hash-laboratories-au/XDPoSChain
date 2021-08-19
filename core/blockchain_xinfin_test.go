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
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/XDPoS"
	"github.com/ethereum/go-ethereum/contracts/validator"
	contractValidator "github.com/ethereum/go-ethereum/contracts/validator/contract"
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

func getCommonBackend(t *testing.T) (common.Address, *backends.SimulatedBackend) {

	fmt.Println("acc1Addr", acc1Addr.Hash().Hex())
	fmt.Println("acc2Addr", acc2Addr.Hash().Hex())
	fmt.Println("acc3Addr", acc3Addr.Hash().Hex())
	fmt.Println("acc4Addr", acc4Addr.Hash().Hex())

	contractBackend := backends.NewSimulatedBackend(core.GenesisAlloc{
		acc1Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		acc2Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		acc3Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		acc4Addr: {Balance: new(big.Int).SetUint64(10000000000)},
	})
	//contractBackend.Commit()

	transactOpts := bind.NewKeyedTransactor(acc1Key)
	validatorCap3 := new(big.Int)
	validatorCap3.SetString("50000000000000000000000", 10)
	validatorCap4 := new(big.Int)
	validatorCap4.SetString("20000000000000000000000004", 10)
	/*
		validatorAddr, _, err := validator.DeployValidator(
			transactOpts, contractBackend,
			[]common.Address{acc3Addr, acc4Addr},
			[]*big.Int{validatorCap3, validatorCap4},
			acc3Addr,
		)
	*/
	validatorAddr, _, _, err := contractValidator.DeployXDCValidator(
		transactOpts,
		contractBackend,
		[]common.Address{acc3Addr, acc4Addr},
		[]*big.Int{validatorCap3, validatorCap4},
		acc3Addr,
		big.NewInt(50000),
		big.NewInt(1),
		big.NewInt(99),
		big.NewInt(100),
		big.NewInt(100),
	)
	if err != nil {
		t.Fatalf("can't deploy root registry: %v", err)
	}
	fmt.Println("validatorAddr: ", validatorAddr.Hex())
	if err != nil {
		t.Fatalf("can't deploy root registry: %v", err)
	}
	contractBackend.Commit()

	//opts := bind.NewKeyedTransactor(acc4Key)
	//opts.Value = new(big.Int).SetUint64(10000)
	//acc4Validator, _ := validator.NewValidator(opts, validatorAddr, contractBackend)
	//acc4Validator.Propose(acc3Addr)

	//contractBackend.Commit()

	return validatorAddr, contractBackend

}

func insertBlock0(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, t *testing.T) *types.Block {
	block := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, 105, blockNum, blockNum*10, nil, 0,
		"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		common.HexToHash("d596671ee88adb9b14be44eaca0e94929bad42ac476bb04db1c15a3021ddd49a"),
	)
	err := blockchain.InsertBlock(block)
	if err != nil {
		t.Fatalf("%v at %d", err, blockNum)
	}
	return block
}

func insertBlock1(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, t *testing.T) *types.Block {
	block := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, 105, blockNum, blockNum*10, nil, 0,
		"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		common.HexToHash("d596671ee88adb9b14be44eaca0e94929bad42ac476bb04db1c15a3021ddd49a"),
	)
	err := blockchain.InsertBlock(block)
	if err != nil {
		t.Fatalf("%v at %d", err, blockNum)
	}
	return block
}

func insertBlockAfter(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, t *testing.T) *types.Block {
	block := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, 105, blockNum, blockNum*10, nil, 0,
		"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		common.HexToHash("964a1ff2dddbd5fee9ac5e5442473fe01000bbe8c422819bc5227debc23a63ab"),
	)
	err := blockchain.InsertBlock(block)
	if err != nil {
		t.Fatalf("%v at %d", err, blockNum)
	}
	return block
}

func insertBlockTxs(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, txs []*types.Transaction, t *testing.T) *types.Block {
	//state, err := blockchain.State()
	//root := state.IntermediateRoot(true)
	block := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, 105, blockNum, blockNum*10, txs, txs[0].Gas(),
		"64c9ee68988c98c83550fa66a2b196ed07cf4bfef7bb1d93a0a736acc51cb36d",
		common.HexToHash("6a8cc62c446d8a3be0d371dfb21a5bde0a08db4b4e4d69c0b44e0e893e27029d"),
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
func transferTx(t *testing.T) *types.Transaction {
	data := []byte{}
	gasPrice := big.NewInt(int64(1))
	gasLimit := uint64(21000)
	amount := big.NewInt(int64(999))
	nonce := uint64(0)
	to := common.HexToAddress("35658f7b2a9E7701e65E7a654659eb1C481d1dC5")
	tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)

	signedTX, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(chainID)), acc4Key)
	if err != nil {
		t.Fatal(err)
	}
	return signedTX
}

func voteTX(t *testing.T) *types.Transaction {
	data := common.Hex2Bytes("6dd7d8ea00000000000000000000000071562b71999873db5b286df957af199ec94617f7")
	gasPrice := big.NewInt(int64(1))
	gasLimit := uint64(22680)
	amountInt := new(big.Int)
	amount, ok := amountInt.SetString("500", 10)
	if !ok {
		t.Fatal("big int init failed")
	}
	nonce := uint64(0)
	to := common.HexToAddress("0x35658f7b2a9e7701e65e7a654659eb1c481d1dc5")
	fmt.Println("to", to.Hex())
	tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)

	ss, _ := json.MarshalIndent(tx, "", "\t")
	fmt.Println(string(ss))

	signedTX, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(chainID)), acc4Key)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := json.MarshalIndent(signedTX, "", "\t")
	fmt.Println(string(s))

	return signedTX
}
func voteFun(validatorAddr common.Address, contractBackend *backends.SimulatedBackend, t *testing.T) {
	acc1Opts := bind.NewKeyedTransactor(acc1Key)
	acc1Opts.Value = new(big.Int).SetInt64(int64(500))
	validator, err := validator.NewValidator(acc1Opts, validatorAddr, contractBackend)
	if err != nil {
		t.Fatalf("can't get current validator: %v", err)
	}
	tx, err := validator.Vote(acc3Addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(tx)
	contractBackend.Commit()
}

func proposeTX(t *testing.T) *types.Transaction {
	data := common.Hex2Bytes("012679510000000000000000000000000d3ab14bbad3d99f4203bd7a11acb94882050e7e")
	//data := []byte{}
	fmt.Println("data", string(data[:]))
	gasPrice := big.NewInt(int64(0))
	gasLimit := uint64(22680)

	amountInt := new(big.Int)
	amount, ok := amountInt.SetString("11000000000000000000000000", 10)
	if !ok {
		t.Fatal("big int init failed")
	}
	nonce := uint64(0)
	to := common.HexToAddress("xdc35658f7b2a9e7701e65e7a654659eb1c481d1dc5")
	tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)

	signedTX, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(chainID)), acc4Key)
	if err != nil {
		t.Fatal(err)
	}
	return signedTX
}
func TestPropose(t *testing.T) {
	//_, blockchain, _ := newXDPoSCanonical(0)

	//validatorAddr, backend := getCommonBackend(t)
	_, backend := getCommonBackend(t)
	blockchain := backend.GetBlockChain()
	state, _ := blockchain.State()
	fmt.Println("account1 balance", state.GetBalance(acc1Addr))
	fmt.Println("account2 balance", state.GetBalance(acc2Addr))
	fmt.Println("account3 balance", state.GetBalance(acc3Addr))
	fmt.Println("account4 balance", state.GetBalance(acc4Addr))
	blockchain.Client = backend
	block := blockchain.Genesis()
	for i := 1; i <= 2; i++ {
		blockCoinBase := fmt.Sprintf("0x111000000000000000000000000000000%03d", i)
		fmt.Println(blockCoinBase)
		var b *types.Block
		if i == 1 {
			b = insertBlock0(blockchain, i, blockCoinBase, block, t)
		} else {
			b = insertBlock1(blockchain, i, blockCoinBase, block, t)
		}
		block = b
	}
	t.Logf("Inserting block with propose at 3...")
	block3CoinBase := "0x2220000000000000000000000000000000000003"
	tx := voteTX(t)
	block = insertBlockTxs(blockchain, 3, block3CoinBase, block, []*types.Transaction{tx}, t)

	//voteFun(validatorAddr, backend, t)

	fmt.Println("validator balance", state.GetBalance(common.HexToAddress("35658f7b2a9E7701e65E7a654659eb1C481d1dC5")))
	state, err := blockchain.State()
	if err != nil {
		t.Fatal(err)
	}
	backend.Commit()
	fmt.Println("validator balance", state.GetBalance(common.HexToAddress("35658f7b2a9E7701e65E7a654659eb1C481d1dC5")))
	fmt.Println("account1 balance", state.GetBalance(acc1Addr))
	fmt.Println("account2 balance", state.GetBalance(acc2Addr))
	fmt.Println("account3 balance", state.GetBalance(acc3Addr))
	fmt.Println("account4 balance", state.GetBalance(acc4Addr))

	for i := 4; i < 5; i++ {
		blockCoinBase := fmt.Sprintf("0x1110000000000000000000000000000000000%3d", i)
		b := insertBlockAfter(blockchain, i, blockCoinBase, block, t)
		block = b
	}
	return
	if blockchain.GetBlockByNumber(10).Header().Coinbase.Hex() != fmt.Sprintf("xdc2220000000000000000000000000000000000010") {
		t.Fatalf("Canonical chain 10 should keep the old 450 block, new insert should remain as uncle %s", blockchain.GetBlockByNumber(10).Header().Coinbase.Hex())
	}
}

func createXDPoSTestBlock(bc *BlockChain, ParentHash, Coinbase string, Difficulty, Number, Time int, txs []*types.Transaction, gasUsed uint64, ReceiptHash string, Root common.Hash) *types.Block {
	extraSubstring := "d7830100018358444388676f312e31342e31856c696e75780000000000000000b185dc0d0e917d18e5dbf0746be6597d3331dd27ea0554e6db433feb2e81730b20b2807d33a1527bf43cd3bc057aa7f641609c2551ebe2fd575f4db704fbf38101"
	UncleHash := "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
	TxHash := "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
	//ReceiptHash = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
	//Root := "0xc99c095e53ff1afe3b86750affd13c7550a2d24d51fb8e41b3c3ef2ea8274bcc"
	extraByte, _ := hex.DecodeString(extraSubstring)
	header := types.Header{
		ParentHash:  common.HexToHash(ParentHash),
		UncleHash:   common.HexToHash(UncleHash),
		TxHash:      common.HexToHash(TxHash),
		ReceiptHash: common.HexToHash(ReceiptHash),
		Root:        Root,
		Coinbase:    common.HexToAddress(Coinbase),
		Difficulty:  big.NewInt(int64(Difficulty)),
		Number:      big.NewInt(int64(Number)),
		GasLimit:    1200000000,
		Time:        big.NewInt(int64(Time)),
		Extra:       extraByte,
		GasUsed:     gasUsed,
	}

	//root := state.IntermediateRoot(true)
	var block *types.Block
	if len(txs) == 0 {
		block = types.NewBlockWithHeader(&header)
	} else {

		state, err := bc.State()
		code := state.GetCode(common.HexToAddress("xdc35658f7b2a9E7701e65E7a654659eb1C481d1dC5"))
		fmt.Println("state code:", code)
		//gp := new(GasPool).AddGas(header.GasLimit)
		//usedGas := uint64(0)
		root := state.IntermediateRoot(true)
		fmt.Println("Before Apply Root ===========================", root.Hex())
		header.TxHash = common.HexToHash("c9cc29258dd0fdbb4cc77f1d213bf1b50063f28906dcc2eb4ef66eda4622fe4a")
		//receipt, _, err := ApplyTransaction(bc.Config(), bc, nil, gp, state, &header, txs[0], &usedGas, vm.Config{})
		//fmt.Println("receipt", receipt)
		if err != nil {
			fmt.Printf("%v when creating block", err)
		}
		receipt := &types.Receipt{Status: 1, CumulativeGasUsed: 22680}
		fmt.Println("receipt", receipt)
		//header.GasUsed = usedGas
		state, err = bc.State()
		//root = state.IntermediateRoot(true)
		//fmt.Println("After Apply Root ================================", root.Hex())
		//header.Root = root
		//header.Root = root
		//header.Root = common.HexToHash("413a27146ef7591ab6137451d36809cb565ef548599227bd073a2a8bfebcdf9e")
		header.UncleHash = types.CalcUncleHash(nil)
		block = types.NewBlock(&header, txs, nil, []*types.Receipt{receipt})
		//root = state.IntermediateRoot(true)
	}
	return block
}

// newXDPoSCanonical creates a chain database, and injects a deterministic canonical
// chain. Depending on the full flag, if creates either a full block chain or a
// header only chain.
func newXDPoSCanonical(n int) (ethdb.Database, *BlockChain, error) {
	// Initialize a fresh chain with only a genesis block
	accountBalance := new(big.Int)
	accountBalance.SetString("3000000000000000000000000000", 10)
	gspec := &Genesis{
		Config:   params.TestChainConfig,
		GasLimit: 1200000000,
		Alloc: GenesisAlloc{
			acc1Addr: {Balance: accountBalance},
			acc2Addr: {Balance: accountBalance},
			acc3Addr: {Balance: accountBalance},
			acc4Addr: {Balance: accountBalance},
		},
	}
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
