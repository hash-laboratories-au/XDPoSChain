package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTimeoutPool(t *testing.T) {
	assert := assert.New(t)
	pool := NewTimeoutPool(2) // 2 is the cert size
	pool.SetNewRound(1)
	timeout1 := Timeout{Round: 1, Signature: []byte{1}}
	timeout2 := Timeout{Round: 1, Signature: []byte{2}}
	timeout3 := Timeout{Round: 1, Signature: []byte{3}}
	assert.Nil(pool.AddTimeout(&timeout1), "timeout pool should return nil")
	assert.Nil(pool.AddTimeout(&timeout1), "timeout pool should return nil (again)")
	assert.NotNil(pool.AddTimeout(&timeout2), "timeout pool should generate TC")
	assert.Nil(pool.AddTimeout(&timeout3), "timeout pool should return nil")
	pool = NewTimeoutPool(3) // 3 is the cert size
	pool.SetNewRound(1)
	assert.Nil(pool.AddTimeout(&timeout1), "timeout pool should return nil")
	assert.Nil(pool.AddTimeout(&timeout2), "timeout pool should return nil")
	assert.Equal(len(pool.hashToTimeout), 2)
	pool.SetNewRound(2)
	assert.Equal(len(pool.hashToTimeout), 0)
}
