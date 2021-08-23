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
	acc1Key, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	acc2Key, _ = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	acc3Key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	acc4Key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee04aefe388d1e14474d32c45c72ce7b7a")
	acc1Addr   = crypto.PubkeyToAddress(acc1Key.PublicKey) //xdc703c4b2bD70c169f5717101CaeE543299Fc946C7
	acc2Addr   = crypto.PubkeyToAddress(acc2Key.PublicKey) //xdc0D3ab14BBaD3D99F4203bd7a11aCB94882050E7e
	acc3Addr   = crypto.PubkeyToAddress(acc3Key.PublicKey) //xdc71562b71999873DB5b286dF957af199Ec94617F7
	acc4Addr   = crypto.PubkeyToAddress(acc4Key.PublicKey) //xdc5F74529C0338546f82389402a01c31fB52c6f434
	chainID    = int64(1337)
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
	contractBackend1 := backends.NewXDCSimulatedBackend(core.GenesisAlloc{
		acc1Addr: {Balance: new(big.Int).SetUint64(10000000000)},
	})

	transactOpts := bind.NewKeyedTransactor(acc1Key)
	cap := new(big.Int)
	cap.SetString("1000000000", 10)

	var candidates []common.Address
	var caps []*big.Int
	for i := 1; i <= 17; i++ {
		addr := fmt.Sprintf("%02d", i)
		candidates = append(candidates, common.StringToAddress(addr))
		caps = append(caps, cap)
	}

	validatorCap1 := new(big.Int)
	validatorCap2 := new(big.Int)
	validatorCap3 := new(big.Int)
	validatorCap4 := new(big.Int)
	validatorCap1.SetString("10000001", 10)
	validatorCap2.SetString("10000002", 10)
	validatorCap3.SetString("10000003", 10)
	validatorCap4.SetString("10000004", 10)
	caps = append(caps, validatorCap1)
	caps = append(caps, validatorCap2)
	caps = append(caps, validatorCap3)
	caps = append(caps, validatorCap4)

	candidates = append(candidates, acc1Addr)
	candidates = append(candidates, acc2Addr)
	candidates = append(candidates, acc3Addr)
	candidates = append(candidates, acc4Addr)
	// create validator smart contract
	validatorAddr, _, _, err := contractValidator.DeployXDCValidator(
		transactOpts,
		contractBackend1,
		candidates,
		caps,
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
	contractBackend2 := backends.NewXDCSimulatedBackend(core.GenesisAlloc{
		acc1Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		acc2Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		acc3Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		acc4Addr: {Balance: new(big.Int).SetUint64(10000000000)},
		common.HexToAddress(common.MasternodeVotingSMC): {Balance: new(big.Int).SetUint64(1), Code: code, Storage: storage},
	})

	return contractBackend2

}

func voteTX(gasLimit uint64, nonce uint64, addr string) (*types.Transaction, error) {
	vote := "6dd7d8ea"
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

	signedTX, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(chainID)), acc4Key)
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
		block, err := insertBlock(blockchain, i, blockCoinBase, currentBlock, "c0abb331585cef76dda3c941b1d94b14e523c28bfb394075ae02e8e2973ed940")
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
	tx, err := voteTX(78185, 0, acc1Addr.String())
	if err != nil {
		t.Fatal(err)
	}

	blockA, err := insertBlockTxs(blockchain, 10, blockCoinbaseA, currentBlock, []*types.Transaction{tx}, "6736596e722b0565537c711ee43ec998f48a18a6fc7d81546071f39c67cf5934")
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

//Should call updateM1 and update snapshot when a forked block(at gap block number) is inserted back into main chain (Edge case)
func TestCallUpdateM1WhenForkedBlockBackToMainChain(t *testing.T) {

	blockchain, backend, currentBlock := PrepareXDCTestBlockChain(t)

	// Insert first Block 10 A
	t.Logf("Inserting block with propose at 10 A...")
	blockCoinbaseA := "0xaaa0000000000000000000000000000000000010"
	tx, err := voteTX(78185, 0, acc1Addr.String())
	if err != nil {
		t.Fatal(err)
	}

	blockA, err := insertBlockTxs(blockchain, 10, blockCoinbaseA, currentBlock, []*types.Transaction{tx}, "6736596e722b0565537c711ee43ec998f48a18a6fc7d81546071f39c67cf5934")
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

	// Insert forked Block 10 B
	t.Logf("Inserting block with propose at 10 B...")

	blockCoinBase10B := "0xbbb0000000000000000000000000000000000010"
	tx, err = voteTX(78185, 0, acc2Addr.String())
	if err != nil {
		t.Fatal(err)
	}

	blockB, err := insertBlockTxs(blockchain, 10, blockCoinBase10B, currentBlock, []*types.Transaction{tx}, "bae86f075f28838810e386e97804c02f9ae4f1c0148cf2ab191d4b7c29ab5088")
	if err != nil {
		t.Fatal(err)
	}
	signers, err = GetSnapshotSigner(blockchain, blockB.Header())
	if err != nil {
		t.Fatal(err)
	}
	if signers[acc4Addr.Hex()] != true {
		debugMessage(backend, signers, t)
		t.Fatalf("account 4 should sit in the signer list as previos block result")
	}

	//Insert block 11 parent is 11 B
	t.Logf("Inserting block with propose at 11 B...")

	blockCoinBase11B := "0xbbb0000000000000000000000000000000000011"
	block11B, err := insertBlock(blockchain, 11, blockCoinBase11B, blockB, "bae86f075f28838810e386e97804c02f9ae4f1c0148cf2ab191d4b7c29ab5088")

	if err != nil {
		t.Fatal(err)
	}
	signers, err = GetSnapshotSigner(blockchain, block11B.Header())
	if err != nil {
		t.Fatal(err)
	}
	if signers[acc2Addr.Hex()] != true {
		debugMessage(backend, signers, t)
		t.Fatalf("account 2 should sit in the signer list")
	}
}

// insert Block without transcation attached
func insertBlock(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, root string) (*types.Block, error) {
	block := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, blockNum, nil,
		"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		common.HexToHash(root),
	)
	err := blockchain.InsertBlock(block)
	if err != nil {
		return nil, err
	}
	return block, nil
}

// insert Block with transcation attached
func insertBlockTxs(blockchain *BlockChain, blockNum int, blockCoinBase string, parentBlock *types.Block, txs []*types.Transaction, root string) (*types.Block, error) {
	block := createXDPoSTestBlock(
		blockchain,
		parentBlock.Hash().Hex(),
		blockCoinBase, blockNum, txs,
		"9319777b782ba2c83a33c995481ff894ac96d9a92a1963091346a3e1e386705c",
		common.HexToHash(root),
	)
	err := blockchain.InsertBlock(block)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func createXDPoSTestBlock(bc *BlockChain, parentHash, coinbase string, number int, txs []*types.Transaction, receiptHash string, root common.Hash) *types.Block {
	extraSubstring := "d7830100018358444388676f312e31342e31856c696e75780000000000000000b185dc0d0e917d18e5dbf0746be6597d3331dd27ea0554e6db433feb2e81730b20b2807d33a1527bf43cd3bc057aa7f641609c2551ebe2fd575f4db704fbf38101"
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

		fmt.Println("receipt", receipt)

		Bloom := types.BytesToBloom(common.Hex2Bytes("00000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000040000000000000000000000000000000000000000000000000000000000080000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
		/*
			receipt := &types.Receipt{
				Status:            1,
				CumulativeGasUsed: 78185,
				Bloom:             Bloom,

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
		header.Bloom = Bloom
		header.UncleHash = types.CalcUncleHash(nil)
		header.GasUsed = txs[0].Gas()
		block = types.NewBlock(&header, txs, nil, []*types.Receipt{receipt})
	}

	return block
}
