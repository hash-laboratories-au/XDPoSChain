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
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

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
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

type masterNodes map[string]big.Int

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

	// initial helper backend
	contractBackend1 := backends.NewSimulatedBackend(core.GenesisAlloc{
		acc1Addr: {Balance: new(big.Int).SetUint64(10000000000)},
	})

	transactOpts := bind.NewKeyedTransactor(acc1Key)
	validatorCap3 := new(big.Int)
	validatorCap4 := new(big.Int)

	validatorCap3.SetString("10000003", 10)
	validatorCap4.SetString("10000004", 10)

	// create validator smart contract
	validatorAddr, _, _, err := contractValidator.DeployXDCValidator(
		transactOpts,
		contractBackend1,
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

	contractBackend1.Commit()

	// Prepare Code and Storage
	d := time.Now().Add(1000 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()

	code, _ := contractBackend1.CodeAt(ctx, validatorAddr, nil)
	storage := make(map[common.Hash]common.Hash)
	f := func(key, val common.Hash) bool {
		decode := []byte{}
		trim := bytes.TrimLeft(val.Bytes(), "\x00")
		rlp.DecodeBytes(trim, &decode)
		storage[key] = common.BytesToHash(decode)
		log.Info("DecodeBytes", "value", val.String(), "decode", storage[key].String())
		return true
	}
	contractBackend1.ForEachStorageAt(ctx, validatorAddr, nil, f)

	// create test backend with smart contract in it
	contractBackend2 := backends.NewSimulatedBackend(core.GenesisAlloc{
		acc1Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		acc2Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		acc3Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		acc4Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		common.HexToAddress(common.MasternodeVotingSMC): {Balance: new(big.Int).SetUint64(1), Code: code, Storage: storage},
	})

	return contractBackend2

}
func insertGenesisBlock(blockchain *BlockChain) (*types.Block, error) {
	block := blockchain.Genesis()
	err := blockchain.InsertBlock(block)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func insertBlock(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block) (*types.Block, error) {
	block := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, 105, blockNum, blockNum*10, nil, 0,
		"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		common.HexToHash("a582ebd7d65ad51a83483400653576efda95cfafd0ed1adc0d9ec09cbab113cd"),
	)
	err := blockchain.InsertBlock(block)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func insertBlockTxs(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, txs []*types.Transaction) (*types.Block, error) {
	//state, err := blockchain.State()
	//root := state.IntermediateRoot(true)
	block := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, 105, blockNum, blockNum*10, txs, txs[0].Gas(),
		"9319777b782ba2c83a33c995481ff894ac96d9a92a1963091346a3e1e386705c",
		common.HexToHash("5e9e69e943847d340c66542f9121d5a25f49d7a8d29cae408a0bf9723145eb78"),
	)
	err := blockchain.InsertBlock(block)
	if err != nil {
		return nil, err
	}
	return block, nil
}
func insertBlockTxs3A(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, txs []*types.Transaction) (*types.Block, error) {
	//state, err := blockchain.State()
	//root := state.IntermediateRoot(true)
	block := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, 105, blockNum, blockNum*10, txs, txs[0].Gas(),
		"9319777b782ba2c83a33c995481ff894ac96d9a92a1963091346a3e1e386705c",
		common.HexToHash("8d5533e2678a162181e2f5d41b3f4be49802e25eb843106625c26d4142065c91"),
	)
	err := blockchain.InsertBlock(block)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func voteTX(gasLimit uint64, nonce uint64, t *testing.T) *types.Transaction {
	// vote : 6dd7d8ea vote
	// addr3 : 00000000000000000000000071562b71999873db5b286df957af199ec94617f7
	data := common.Hex2Bytes("6dd7d8ea00000000000000000000000071562b71999873db5b286df957af199ec94617f7")
	gasPrice := big.NewInt(int64(0))
	amountInt := new(big.Int)
	amount, ok := amountInt.SetString("60000", 10)
	if !ok {
		t.Fatal("big int init failed")
	}
	to := common.HexToAddress(common.MasternodeVotingSMC)
	tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)

	signedTX, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(chainID)), acc4Key)
	if err != nil {
		t.Fatal(err)
	}

	return signedTX
}

func GetCandidateData(backend bind.ContractBackend, t *testing.T) masterNodes {

	addr := common.HexToAddress(common.MasternodeVotingSMC)
	validator, err := contractValidator.NewXDCValidator(addr, backend)
	if err != nil {
		t.Fatal(err)
	}

	opts := new(bind.CallOpts)
	candidates, err := validator.GetCandidates(opts)
	if err != nil {
		t.Fatal(err)
	}

	ms := make(masterNodes)
	for _, candidate := range candidates {
		v, err := validator.GetCandidateCap(opts, candidate)
		if err != nil {
			t.Fatal(err)
		}
		ms[candidate.String()] = *v
	}
	return ms
}

func TestPropose(t *testing.T) {
	var err error
	backend := getCommonBackend(t)
	blockchain := backend.GetBlockChain()
	blockchain.Client = backend

	currentBlock := blockchain.Genesis()

	for i := 1; i <= 2; i++ {
		blockCoinBase := fmt.Sprintf("0x111000000000000000000000000000000%03d", i)
		block, err := insertBlock(blockchain, i, blockCoinBase, currentBlock)
		if err != nil {
			t.Fatal(err)
		}

		currentBlock = block
	}
	t.Logf("Inserting block with propose at 3...")
	blockCoinBase3A := "0xaaa0000000000000000000000000000000000003"
	tx := voteTX(78185, 0, t)

	_, err = insertBlockTxs(blockchain, 3, blockCoinBase3A, currentBlock, []*types.Transaction{tx})
	if err != nil {
		t.Fatal(err)
	}
	ms := GetCandidateData(backend, t)
	fmt.Println(ms)

	blockCoinBase3B := "0xbbb0000000000000000000000000000000000003"
	tx = voteTX(37117, 1, t)
	_, err = insertBlock(blockchain, 3, blockCoinBase3B, currentBlock)
	if err != nil {
		t.Fatal(err)
	}
	ms = GetCandidateData(backend, t)
	fmt.Println(ms)
	/*
		for i := 4; i < 5; i++ {
			blockCoinBase := fmt.Sprintf("0x1110000000000000000000000000000000000%03d", i)
			b := insertBlockAfter(blockchain, i, blockCoinBase, block, t)
			block = b
		}
	*/
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

		//code := state.GetCode(common.HexToAddress("xdc35658f7b2a9E7701e65E7a654659eb1C481d1dC5"))
		//fmt.Println("state code:", code)
		state, err := bc.State()
		if err != nil {
			fmt.Println("error:", err)
		}
		gp := new(GasPool).AddGas(header.GasLimit)
		usedGas := uint64(0)
		header.TxHash = common.HexToHash("c9cc29258dd0fdbb4cc77f1d213bf1b50063f28906dcc2eb4ef66eda4622fe4a")
		receipt, _, err := ApplyTransaction(bc.Config(), bc, nil, gp, state, &header, txs[0], &usedGas, vm.Config{})

		if err != nil {
			fmt.Printf("%v when creating block", err)
		}
		//fmt.Println("receipt", receipt)
		/*
			receipt := &types.Receipt{
				Status:            1,
				CumulativeGasUsed: 78185,
				Bloom:             types.BytesToBloom(common.Hex2Bytes("00000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
				Logs: []*types.Log{
					//	return fmt.Sprintf(`log: %x %x %x %x %d %x %d`, l.Address, l.Topics, l.Data, l.TxHash, l.TxIndex, l.BlockHash, l.Index)
					{
						Address:     common.HexToAddress("35658f7b2a9e7701e65e7a654659eb1c481d1dc5"),
						Topics:      []common.Hash{common.StringToHash("66a9138482c99e9baf08860110ef332cc0c23b4a199a53593d8db0fc8f96fbfc")},
						Data:        common.Hex2Bytes("0000000000000000000000005f74529c0338546f82389402a01c31fb52c6f43400000000000000000000000071562b71999873db5b286df957af199ec94617f7000000000000000000000000000000000000000000000000000000000000c350"),
						TxHash:      common.StringToHash("9f83055bb924b663da55b64f2eeab967e3f9d65ea7a162f950845e9ed56e64b7"),
						TxIndex:     0,
						BlockHash:   common.StringToHash("42eaa539927574e6a53839548f80510114fb5af7262c3eeb653ec5c943b99f5b"),
						Index:       0,
						BlockNumber: 3,
						Removed:     false,
					},
				},
			}
		*/

		header.Bloom = types.BytesToBloom(common.Hex2Bytes("00000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000040000000000000000000000000000000000000000000000000000000000080000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
		//header.GasUsed = usedGas
		//state, err := bc.State()
		//header.Root = common.HexToHash("413a27146ef7591ab6137451d36809cb565ef548599227bd073a2a8bfebcdf9e")
		header.UncleHash = types.CalcUncleHash(nil)
		block = types.NewBlock(&header, txs, nil, []*types.Receipt{receipt})
		//root = state.IntermediateRoot(true)

	}

	return block
}

//
//
//
//
//
// Backup Function

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

var canonicalSeed = 1

func makeBlockChain(parent *types.Block, n int, engine consensus.Engine, db ethdb.Database, seed int) []*types.Block {
	blocks, _ := GenerateChain(params.TestChainConfig, parent, engine, db, n, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: byte(seed), 19: byte(i)})
	})
	return blocks
}

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

func insertBlockAfter(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, t *testing.T) *types.Block {
	block := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, 105, blockNum, blockNum*10, nil, 0,
		"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		common.HexToHash("ba9e18937a3347c2acbbaeb93b1add58fba4c5ce97296251a7b92323c11e7e5a"),
	)
	err := blockchain.InsertBlock(block)
	if err != nil {
		t.Fatalf("%v at %d", err, blockNum)
	}
	return block
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
