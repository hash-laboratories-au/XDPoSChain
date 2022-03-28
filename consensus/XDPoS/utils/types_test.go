package utils

import (
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/stretchr/testify/assert"
)

func toyExtraFields() *ExtraFields_v2 {
	round := Round(307)
	blockInfo := &BlockInfo{Hash: common.BigToHash(big.NewInt(2047)), Round: round - 1, Number: big.NewInt(900)}
	signature := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	signatures := []Signature{signature}
	quorumCert := &QuorumCert{ProposedBlockInfo: blockInfo, Signatures: signatures, GapNumber: 450}
	e := &ExtraFields_v2{Round: round, QuorumCert: quorumCert}
	return e
}
func TestExtraFieldsEncodeDecode(t *testing.T) {
	extraFields := toyExtraFields()
	encoded, err := extraFields.EncodeToBytes()
	if err != nil {
		t.Errorf("Error when encoding extra fields")
	}
	var decoded ExtraFields_v2
	err = DecodeBytesExtraFields(encoded, &decoded)
	if err != nil {
		t.Errorf("Error when decoding extra fields")
	}
	if !reflect.DeepEqual(*extraFields, decoded) {
		t.Fatalf("Decoded not equal to original extra field, original: %v; decoded: %v", extraFields, decoded)
	}
}

func TestHashAndSigHash(t *testing.T) {
	round := Round(307)
	gapNumer := uint64(450)
	blockInfo1 := &BlockInfo{Hash: common.BigToHash(big.NewInt(2047)), Round: round - 1, Number: big.NewInt(900)}
	blockInfo2 := &BlockInfo{Hash: common.BigToHash(big.NewInt(4095)), Round: round - 1, Number: big.NewInt(900)}
	voteForSign1 := &VoteForSign{ProposedBlockInfo: blockInfo1, GapNumber: gapNumer}
	voteForSign2 := &VoteForSign{ProposedBlockInfo: blockInfo2, GapNumber: gapNumer}
	signature1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	signature2 := []byte{1, 2, 3, 4, 5, 6, 7, 7}
	signatures1 := []Signature{signature1}
	signatures2 := []Signature{signature2}
	quorumCert1 := &QuorumCert{ProposedBlockInfo: blockInfo1, Signatures: signatures1, GapNumber: 450}
	quorumCert2 := &QuorumCert{ProposedBlockInfo: blockInfo1, Signatures: signatures2, GapNumber: 450}
	vote1 := Vote{ProposedBlockInfo: blockInfo1, Signature: signature1, GapNumber: gapNumer}
	vote2 := Vote{ProposedBlockInfo: blockInfo1, Signature: signature2, GapNumber: gapNumer}
	if vote1.Hash() == vote2.Hash() {
		t.Fatalf("Hash of two votes shouldn't equal")
	}
	timeout1 := Timeout{Round: 10, Signature: signature1}
	timeout2 := Timeout{Round: 10, Signature: signature2}
	if timeout1.Hash() == timeout2.Hash() {
		t.Fatalf("Hash of two timeouts shouldn't equal")
	}
	syncInfo1 := SyncInfo{HighestQuorumCert: quorumCert1}
	syncInfo2 := SyncInfo{HighestQuorumCert: quorumCert2}
	if syncInfo1.Hash() == syncInfo2.Hash() {
		t.Fatalf("Hash of two sync info shouldn't equal")
	}
	if VoteSigHash(voteForSign1) == VoteSigHash(voteForSign2) {
		t.Fatalf("SigHash of two block info shouldn't equal")
	}
	round2 := Round(999)
	if TimeoutSigHash(&TimeoutForSign{
		Round:     round,
		GapNumber: 450,
	}) == TimeoutSigHash(&TimeoutForSign{
		Round:     round2,
		GapNumber: 450,
	}) {
		t.Fatalf("SigHash of two round shouldn't equal")
	}
}

func TestPoolKeyFormat(t *testing.T) {
	voteMsg := &Vote{
		ProposedBlockInfo: &BlockInfo{
			Hash:   common.Hash{1},
			Round:  5,
			Number: big.NewInt(4),
		},
		Signature: []byte{},
		GapNumber: 450,
	}

	voteKey := strings.Split(voteMsg.PoolKey(), ":")
	assert.Equal(t, "5", voteKey[0])
	assert.Equal(t, "4", voteKey[1])
	assert.Equal(t, common.Hash{1}.String(), voteKey[2])
}
