package XDPoS

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type Masternode struct {
	Address common.Address
	Stake   *big.Int
}
