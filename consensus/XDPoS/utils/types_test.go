package utils

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

func testExtraFields() *ExtraFields_v2 {
	round := uint64(307)
	block_info := BlockInfo{Hash: common.BigToHash(big.NewInt(2047)), Round: round - 1, Number: big.NewInt(1)}
	signatures := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	quorum_cert := QuorumCertType{ProposedBlockInfo: block_info, Signatures: signatures}
	e := &ExtraFields_v2{Round: round, QuorumCert: quorum_cert}
	return e
}
func TestExtraFieldsEncodeDecode(t *testing.T) {
	extraFields := testExtraFields()
	encoded, err := extraFields.Encode()
	if err != nil {
		t.Errorf("Error when encoding extra fields")
	}
	decoded, err := DecodeExtraFields(encoded)
	if err != nil {
		t.Errorf("Error when decoding extra fields")
	}
	if !reflect.DeepEqual(extraFields, decoded) {
		t.Fatalf("Decoded not equal to original extra field, original: %v; decoded: %v", extraFields, decoded)
	}
}
