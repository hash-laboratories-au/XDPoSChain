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

package end_to_end

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/XDPoS"
	contractValidator "github.com/ethereum/go-ethereum/contracts/validator/contract"
	"github.com/ethereum/go-ethereum/core"
	. "github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

type masterNodes map[string]big.Int
type signersList map[string]bool

var (
	acc1Key, _  = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	acc2Key, _  = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	acc3Key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	voterKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee04aefe388d1e14474d32c45c72ce7b7a")
	acc1Addr    = crypto.PubkeyToAddress(acc1Key.PublicKey)  //xdc703c4b2bD70c169f5717101CaeE543299Fc946C7
	acc2Addr    = crypto.PubkeyToAddress(acc2Key.PublicKey)  //xdc0D3ab14BBaD3D99F4203bd7a11aCB94882050E7e
	acc3Addr    = crypto.PubkeyToAddress(acc3Key.PublicKey)  //xdc71562b71999873DB5b286dF957af199Ec94617F7
	voterAddr   = crypto.PubkeyToAddress(voterKey.PublicKey) //xdc5F74529C0338546f82389402a01c31fB52c6f434
	chainID     = int64(1337)
)

func debugMessage(backend *backends.SimulatedBackend, signers signersList, t *testing.T) {
	ms := GetCandidateFromCurrentSmartContract(backend, t)
	fmt.Println("=== current smart contract")
	for nodeAddr, cap := range ms {
		if !strings.Contains(nodeAddr, "000000000000000000000000000000000000") { //remove defaults
			fmt.Println(nodeAddr, cap)
		}
	}
	fmt.Println("=== this block signer list")
	for signer := range signers {
		if !strings.Contains(signer, "000000000000000000000000000000000000") { //remove defaults
			fmt.Println(signer)
		}
	}
}

func getCommonBackend(t *testing.T) *backends.SimulatedBackend {

	// initial helper backend
	contractBackendForSC := backends.NewXDCSimulatedBackend(core.GenesisAlloc{
		voterAddr: {Balance: new(big.Int).SetUint64(10000000000)},
	})

	transactOpts := bind.NewKeyedTransactor(voterKey)

	var candidates []common.Address
	var caps []*big.Int
	defalutCap := new(big.Int)
	defalutCap.SetString("1000000000", 10)

	for i := 1; i <= 16; i++ {
		addr := fmt.Sprintf("%02d", i)
		candidates = append(candidates, common.StringToAddress(addr))
		caps = append(caps, defalutCap)
	}

	acc1Cap, acc2Cap, acc3Cap, voterCap := new(big.Int), new(big.Int), new(big.Int), new(big.Int)

	acc1Cap.SetString("10000001", 10)
	acc2Cap.SetString("10000002", 10)
	acc3Cap.SetString("10000003", 10)
	voterCap.SetString("1000000000", 10)

	caps = append(caps, voterCap, acc1Cap, acc2Cap, acc3Cap)
	candidates = append(candidates, voterAddr, acc1Addr, acc2Addr, acc3Addr)
	// create validator smart contract
	validatorSCAddr, _, _, err := contractValidator.DeployXDCValidator(
		transactOpts,
		contractBackendForSC,
		candidates,
		caps,
		voterAddr, // first owner, not used
		big.NewInt(50000),
		big.NewInt(1),
		big.NewInt(99),
		big.NewInt(100),
		big.NewInt(100),
	)
	if err != nil {
		t.Fatalf("can't deploy root registry: %v", err)
	}

	contractBackendForSC.Commit() // Write into database(state)

	// Prepare Code and Storage
	d := time.Now().Add(1000 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()

	code, _ := contractBackendForSC.CodeAt(ctx, validatorSCAddr, nil)
	storage := make(map[common.Hash]common.Hash)
	f := func(key, val common.Hash) bool {
		decode := []byte{}
		trim := bytes.TrimLeft(val.Bytes(), "\x00")
		rlp.DecodeBytes(trim, &decode)
		storage[key] = common.BytesToHash(decode)
		log.Info("DecodeBytes", "value", val.String(), "decode", storage[key].String())
		return true
	}
	contractBackendForSC.ForEachStorageAt(ctx, validatorSCAddr, nil, f)

	// create test backend with smart contract in it
	contractBackend2 := backends.NewXDCSimulatedBackend(core.GenesisAlloc{
		acc1Addr:  {Balance: new(big.Int).SetUint64(10000000000)},
		acc2Addr:  {Balance: new(big.Int).SetUint64(10000000000)},
		acc3Addr:  {Balance: new(big.Int).SetUint64(10000000000)},
		voterAddr: {Balance: new(big.Int).SetUint64(10000000000)},
		common.HexToAddress(common.MasternodeVotingSMC): {Balance: new(big.Int).SetUint64(1), Code: code, Storage: storage}, // Binding the MasternodeVotingSMC with newly created 'code' for SC execution
	})

	return contractBackend2

}

/*
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
*/

func voteTX(gasLimit uint64, nonce uint64, addr string) (*types.Transaction, error) {
	vote := "6dd7d8ea" // VoteMethod = "0x6dd7d8ea"
	action := fmt.Sprintf("%s%s%s", vote, "000000000000000000000000", addr[3:])
	data := common.Hex2Bytes(action)
	gasPrice := big.NewInt(int64(0))
	amountInt := new(big.Int)
	amount, ok := amountInt.SetString("60000", 10)
	if !ok {
		return nil, fmt.Errorf("big int init failed")
	}
	to := common.HexToAddress(common.MasternodeVotingSMC)
	tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)

	signedTX, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(chainID)), voterKey)
	if err != nil {
		return nil, err
	}

	return signedTX, nil
}
func UpdateSigner(bc *BlockChain) error {
	err := bc.UpdateM1()
	return err
}

func GetSnapshotSigner(bc *BlockChain, header *types.Header) (signersList, error) {
	engine := bc.Engine().(*XDPoS.XDPoS)
	snap, err := engine.GetSnapshot(bc, header)
	if err != nil {
		return nil, err

	}
	ms := make(signersList)

	for addr := range snap.Signers {
		ms[addr.Hex()] = true
	}
	return ms, nil

}

func GetCandidateFromCurrentSmartContract(backend bind.ContractBackend, t *testing.T) masterNodes {
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

func PrepareXDCTestBlockChain(t *testing.T) (*BlockChain, *backends.SimulatedBackend, *types.Block) {
	// Preparation
	var err error
	backend := getCommonBackend(t)
	blockchain := backend.GetBlockChain()
	blockchain.Client = backend

	currentBlock := blockchain.Genesis()

	// Insert initial 9 blocks
	for i := 1; i <= 9; i++ {
		blockCoinBase := fmt.Sprintf("0x111000000000000000000000000000000%03d", i)
		merkleRoot := "35999dded35e8db12de7e6c1471eb9670c162eec616ecebbaf4fddd4676fb930"
		block, err := insertBlock(blockchain, i, blockCoinBase, currentBlock, merkleRoot)
		if err != nil {
			t.Fatal(err)
		}
		currentBlock = block
	}
	// Update Signer as there is no previous signer assigned
	err = UpdateSigner(blockchain)
	if err != nil {
		t.Fatal(err)
	}

	return blockchain, backend, currentBlock
}

//Should call updateM1 at gap block, and update the snapshot if there are SM transactions involved
func TestCallUpdateM1WithSmartContractTranscation(t *testing.T) {

	blockchain, backend, currentBlock := PrepareXDCTestBlockChain(t)
	// Insert first Block 10 A
	t.Logf("Inserting block with propose at 10 A...")
	blockCoinbaseA := "0xaaa0000000000000000000000000000000000010"
	tx, err := voteTX(37117, 0, acc1Addr.String())
	if err != nil {
		t.Fatal(err)
	}

	//Get from block validator error message
	merkleRoot := "46234e9cd7e85a267f7f0435b15256a794a2f6d65cc98cdbd21dcd10a01d9772"
	blockA, err := insertBlockTxs(blockchain, 10, blockCoinbaseA, currentBlock, []*types.Transaction{tx}, merkleRoot)
	if err != nil {
		t.Fatal(err)
	}

	signers, err := GetSnapshotSigner(blockchain, blockA.Header())
	if err != nil {
		t.Fatal(err)
	}
	if signers[acc1Addr.Hex()] != true {
		debugMessage(backend, signers, t)
		t.Fatalf("account 1 should sit in the signer list")
	}
}

// Should have previous smart contract transcation, then have 2 blocks at Gap Step.
// Both Block should have update signer whenever they be added into main chain.

func Test1(t *testing.T) {
}

// Should call updateM1 and update snapshot when a forked block(at gap block number) is inserted back into main chain (Edge case)
func TestCallUpdateM1WhenForkedBlockBackToMainChain(t *testing.T) {

	blockchain, backend, currentBlock := PrepareXDCTestBlockChain(t)

	// Check initial signer
	signers, err := GetSnapshotSigner(blockchain, blockchain.CurrentBlock().Header())
	if err != nil {
		t.Fatal(err)
	}
	if signers[acc3Addr.Hex()] != true {
		debugMessage(backend, signers, t)
		t.Fatalf("voterAddr should sit in the signer list")
	}

	// Insert first Block 10 A
	t.Logf("Inserting block with propose at 10 A...")
	blockCoinbaseA := "0xaaa0000000000000000000000000000000000010"
	tx, err := voteTX(37117, 0, acc1Addr.String())
	if err != nil {
		t.Fatal(err)
	}

	merkleRoot := "46234e9cd7e85a267f7f0435b15256a794a2f6d65cc98cdbd21dcd10a01d9772"
	blockA, err := insertBlockTxs(blockchain, 10, blockCoinbaseA, currentBlock, []*types.Transaction{tx}, merkleRoot)
	if err != nil {
		t.Fatal(err)
	}

	signers, err = GetSnapshotSigner(blockchain, blockA.Header())
	if err != nil {
		t.Fatal(err)
	}
	if signers[acc1Addr.Hex()] != true {
		debugMessage(backend, signers, t)
		t.Fatalf("account 1 should sit in the signer list")
	}

	// Insert forked Block 10 B
	t.Logf("Inserting block with propose at 10 B...")

	blockCoinBase10B := "0xbbb0000000000000000000000000000000000010"
	tx, err = voteTX(37117, 0, acc2Addr.String())
	if err != nil {
		t.Fatal(err)
	}

	merkleRoot = "068dfa09d7b4093441c0cc4d9807a71bc586f6101c072d939b214c21cd136eb3"
	block10B, err := insertBlockTxs(blockchain, 10, blockCoinBase10B, currentBlock, []*types.Transaction{tx}, merkleRoot)
	if err != nil {
		t.Fatal(err)
	}
	signers, err = GetSnapshotSigner(blockchain, block10B.Header())
	if err != nil {
		t.Fatal(err)
	}
	// Should not run the `updateM1` for forked chain, hence account3 still exit
	if signers[acc3Addr.Hex()] != true {
		debugMessage(backend, signers, t)
		t.Fatalf("account 3 should sit in the signer list as previos block result")
	}

	//Insert block 11 parent is 11 B
	t.Logf("Inserting block with propose at 11 B...")

	blockCoinBase11B := "0xbbb0000000000000000000000000000000000011"
	merkleRoot = "068dfa09d7b4093441c0cc4d9807a71bc586f6101c072d939b214c21cd136eb3"
	block11B, err := insertBlock(blockchain, 11, blockCoinBase11B, block10B, merkleRoot)

	if err != nil {
		t.Fatal(err)
	}

	signers, err = GetSnapshotSigner(blockchain, block10B.Header())
	if err != nil {
		t.Fatal(err)
	}
	if signers[acc2Addr.Hex()] != true {
		debugMessage(backend, signers, t)
		t.Fatalf("account 2 should sit in the signer list")
	}

	signers, err = GetSnapshotSigner(blockchain, block11B.Header())
	if err != nil {
		t.Fatal(err)
	}
	if signers[acc2Addr.Hex()] != true {
		debugMessage(backend, signers, t)
		t.Fatalf("account 2 should sit in the signer list")
	}

	signers, err = GetSnapshotSigner(blockchain, blockchain.CurrentBlock().Header())
	if err != nil {
		t.Fatal(err)
	}
	if signers[acc2Addr.Hex()] != true {
		debugMessage(backend, signers, t)
		t.Fatalf("acc2Addr should sit in the signer list")
	}
}

// insert Block without transcation attached
func insertBlock(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, root string) (*types.Block, error) {
	block, err := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, blockNum, nil,
		"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		common.HexToHash(root),
	)
	if err != nil {
		return nil, err
	}

	err = blockchain.InsertBlock(block)
	if err != nil {
		return nil, err
	}
	return block, nil
}

// insert Block with transcation attached
func insertBlockTxs(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, txs []*types.Transaction, root string) (*types.Block, error) {
	block, err := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, blockNum, txs,
		"9319777b782ba2c83a33c995481ff894ac96d9a92a1963091346a3e1e386705c",
		common.HexToHash(root),
	)
	if err != nil {
		return nil, err
	}

	err = blockchain.InsertBlock(block)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func createXDPoSTestBlock(bc *BlockChain, parentHash, coinbase string, number int, txs []*types.Transaction, receiptHash string, root common.Hash) (*types.Block, error) {
	extraSubstring := "d7830100018358444388676f312e31342e31856c696e75780000000000000000b185dc0d0e917d18e5dbf0746be6597d3331dd27ea0554e6db433feb2e81730b20b2807d33a1527bf43cd3bc057aa7f641609c2551ebe2fd575f4db704fbf38101" // Grabbed from existing mainnet block, it does not have any meaning except for the length validation
	//ReceiptHash = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
	//Root := "0xc99c095e53ff1afe3b86750affd13c7550a2d24d51fb8e41b3c3ef2ea8274bcc"
	extraByte, _ := hex.DecodeString(extraSubstring)
	header := types.Header{
		ParentHash:  common.HexToHash(parentHash),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Root:        root,
		Coinbase:    common.HexToAddress(coinbase),
		Difficulty:  big.NewInt(int64(1)),
		Number:      big.NewInt(int64(number)),
		GasLimit:    1200000000,
		Time:        big.NewInt(int64(number * 10)),
		Extra:       extraByte,
	}

	var block *types.Block
	if len(txs) == 0 {
		block = types.NewBlockWithHeader(&header)
	} else {

		// Prepare Receipt
		statedb, err := bc.StateAt(bc.GetBlockByNumber(uint64(number - 1)).Root()) //Get parent root
		if err != nil {
			return nil, fmt.Errorf("%v when get state", err)
		}
		gp := new(GasPool).AddGas(header.GasLimit)
		usedGas := uint64(0)
		statedb.Prepare(txs[0].Hash(), header.Hash(), 0)
		receipt, _, err := ApplyTransaction(bc.Config(), bc, &header.Coinbase, gp, statedb, &header, txs[0], &usedGas, vm.Config{})
		if err != nil {
			return nil, fmt.Errorf("%v when creating block", err)
		}
		header.GasUsed = txs[0].Gas()
		block = types.NewBlock(&header, txs, nil, []*types.Receipt{receipt})
	}

	return block, nil
}
