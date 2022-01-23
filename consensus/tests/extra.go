package tests

import (
	"bytes"
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

var (
	acc1Key1, _ = crypto.HexToECDSA("0df9054384c57a61746aa80351b9d8140ed8599f8b45bca7c28c105959f02af7")
	acc2Key2, _ = crypto.HexToECDSA("0df9054384c57a61746aa80351b9d8140ed8599f8b45bca7c28c105959f02af8")
	acc3Key3, _ = crypto.HexToECDSA("0df9054384c57a61746aa80351b9d8140ed8599f8b45bca7c28c105959f02af9")
	acc4Key4, _ = crypto.HexToECDSA("0df9054384c57a61746aa80351b9d8140ed8599f8b45bca7c28c105959f02af0")
	acc1Addr1   = crypto.PubkeyToAddress(acc1Key1.PublicKey)
	acc2Addr2   = crypto.PubkeyToAddress(acc2Key2.PublicKey)
	acc3Addr3   = crypto.PubkeyToAddress(acc3Key3.PublicKey)
	acc4Addr4   = crypto.PubkeyToAddress(acc4Key4.PublicKey)
	// chainID    = int64(1337)
)

func CreateExtra() {
	var headerExtra []byte
	if len(headerExtra) < utils.ExtraVanity {
		headerExtra = append(headerExtra, bytes.Repeat([]byte{0x00}, utils.ExtraVanity-len(headerExtra))...)
	}
	headerExtra = headerExtra[:utils.ExtraVanity]
	var masternodes []common.Address
	masternodes = append(masternodes, acc1Addr1, acc2Addr2, acc3Addr3, acc4Addr4)
	for _, masternode := range masternodes {
		headerExtra = append(headerExtra, masternode[:]...)
	}
	headerExtra = append(headerExtra, make([]byte, utils.ExtraSeal)...)

	// Sign all the things for v1 block use v1 sigHash function
	// sighash, err := signFn(accounts.Account{Address: acc4Addr}, blockchain.Engine().(*XDPoS.XDPoS).SigHash(header).Bytes())
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// copy(headerExtra[len(headerExtra)-utils.ExtraSeal:], sighash)

	fmt.Println(common.Bytes2Hex(headerExtra))
}
