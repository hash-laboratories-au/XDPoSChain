package engine_v2

import (
	"fmt"
	"math/big"
	"reflect"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
)

const (
	NUM_OF_FORENSICS_QC = 3
)

type ForensicProof struct {
	QcWithSmallerRound          utils.QuorumCert
	QcWithLargerRound           utils.QuorumCert
	DivergingHash               common.Hash
	HashesTillSmallerRoundQc    []common.Hash
	HashesTillLargerRoundQc     []common.Hash
	AcrossEpochs                bool
	QcWithSmallerRoundAddresses []common.Address
	QcWithLargerRoundAddresses  []common.Address
}

// Forensics instance. Placeholder for future properties to be added
type Forensics struct {
	HighestCommittedQCs []utils.QuorumCert
}

// Initiate a forensics process
func NewForensics() *Forensics {
	return &Forensics{}
}

/*
	Entry point for processing forensics.
	Triggered once processQC is successfully.
	Forensics runs in a seperate go routine as its no system critical
	Link to the flow diagram: https://hashlabs.atlassian.net/wiki/spaces/HASHLABS/pages/97878029/Forensics+Diagram+flow
*/
func (f *Forensics) ProcessForensics(chain consensus.ChainReader, incomingQC utils.QuorumCert) error {
	log.Info("Received a QC in forensics", "QC", incomingQC)
	// Clone the values to a temporary variable
	highestCommittedQCs := f.HighestCommittedQCs
	if len(highestCommittedQCs) != NUM_OF_FORENSICS_QC {
		log.Error("[ProcessForensics] HighestCommittedQCs value not set", "incomingQcProposedBlockHash", incomingQC.ProposedBlockInfo.Hash, "incomingQcProposedBlockNumber", incomingQC.ProposedBlockInfo.Number.Uint64(), "incomingQcProposedBlockRound", incomingQC.ProposedBlockInfo.Round)
		return fmt.Errorf("HighestCommittedQCs value not set")
	}
	// Find the QC1 and QC2. We only care 2 parents in front of the incomingQC. The returned value contains QC1, QC2 and QC3(the incomingQC)
	quorunCerts, err := f.findParentsQc(chain, incomingQC, 2)
	if err != nil {
		return err
	}
	isOnTheChain, err := f.checkQCsOnTheSameChain(chain, highestCommittedQCs, quorunCerts)
	if err != nil {
		return err
	}
	if isOnTheChain {
		// Passed the checking, nothing suspecious.
		log.Debug("[ProcessForensics] Passed forensics checking, nothing suspecious need to be reported", "incomingQcProposedBlockHash", incomingQC.ProposedBlockInfo.Hash, "incomingQcProposedBlockNumber", incomingQC.ProposedBlockInfo.Number.Uint64(), "incomingQcProposedBlockRound", incomingQC.ProposedBlockInfo.Round)
		return nil
	}
	// Trigger the safety Alarm if failed
	return nil
}

// Set the forensics committed QCs list. The order is from grandparent to current header. i.e it shall follow the QC in its header as follow [hcqc1, hcqc2, hcqc3]
func (f *Forensics) SetCommittedQCs(headers []types.Header, incomingQC utils.QuorumCert) error {
	// highestCommitQCs is an array, assign the parentBlockQc and its child as well as its grandchild QC into this array for forensics purposes.
	if len(headers) != NUM_OF_FORENSICS_QC-1 {
		log.Error("[SetCommittedQcs] Received input length not equal to 2", len(headers))
		return fmt.Errorf("Received headers length not equal to 2 ")
	}

	var committedQCs []utils.QuorumCert
	for i, h := range headers {
		var decodedExtraField utils.ExtraFields_v2
		// Decode the qc1 and qc2
		err := utils.DecodeBytesExtraFields(h.Extra, &decodedExtraField)
		if err != nil {
			log.Error("[SetCommittedQCs] Fail to decode extra when committing QC to forensics", "Error", err, "Index", i)
			return err
		}
		if i != 0 {
			if decodedExtraField.QuorumCert.ProposedBlockInfo.Hash != headers[i-1].Hash() {
				log.Error("[SetCommittedQCs] Headers shall be on the same chain and in the right order", "ParentHash", h.ParentHash.Hex(), "headers[i-1].Hash()", headers[i-1].Hash().Hex())
				return fmt.Errorf("Headers shall be on the same chain and in the right order")
			} else if i == len(headers)-1 { // The last header shall be pointed by the incoming QC
				if incomingQC.ProposedBlockInfo.Hash != h.Hash() {
					log.Error("[SetCommittedQCs] incomingQc is not pointing at the last header received", "hash", h.Hash().Hex(), "incomingQC.ProposedBlockInfo.Hash", incomingQC.ProposedBlockInfo.Hash.Hex())
					return fmt.Errorf("incomingQc is not pointing at the last header received")
				}
			}
		}

		committedQCs = append(committedQCs, *decodedExtraField.QuorumCert)
	}
	f.HighestCommittedQCs = append(committedQCs, incomingQC)
	return nil
}

// Last step of forensics which sends out detailed proof to report service.
func (f *Forensics) SendForensicProof() {
}

// Utils function to help find the n-th previous QC. It returns an array of QC in ascending order including the currentQc as the last item in the array
func (f *Forensics) findParentsQc(chain consensus.ChainReader, currentQc utils.QuorumCert, distanceFromCurrrentQc int) ([]utils.QuorumCert, error) {
	var quorumCerts []utils.QuorumCert
	quorumCertificate := currentQc
	// Append the initial value
	quorumCerts = append(quorumCerts, quorumCertificate)
	// Append the parents
	for i := 0; i < distanceFromCurrrentQc; i++ {
		parentHash := quorumCertificate.ProposedBlockInfo.Hash
		parentHeader := chain.GetHeaderByHash(parentHash)
		if parentHeader == nil {
			log.Error("[findParentsQc] Forensics findParentsQc unable to find its parent block header", "BlockNum", parentHeader.Number.Int64(), "ParentHash", parentHash.Hex())
			return nil, fmt.Errorf("Unable to find parent block header in forensics")
		}
		var decodedExtraField utils.ExtraFields_v2
		err := utils.DecodeBytesExtraFields(parentHeader.Extra, &decodedExtraField)
		if err != nil {
			log.Error("[findParentsQc] Error while trying to decode from parent block extra", "BlockNum", parentHeader.Number.Int64(), "ParentHash", parentHash.Hex())
		}
		quorumCertificate = *decodedExtraField.QuorumCert
		quorumCerts = append(quorumCerts, quorumCertificate)
	}
	// The quorumCerts is in the reverse order, we need to flip it
	var quorumCertsInAscendingOrder []utils.QuorumCert
	for i := len(quorumCerts) - 1; i >= 0; i-- {
		quorumCertsInAscendingOrder = append(quorumCertsInAscendingOrder, quorumCerts[i])
	}
	return quorumCertsInAscendingOrder, nil
}

// Check whether the given QCs are on the same chain as the stored committed QCs(f.HighestCommittedQCs) regardless their orders
func (f *Forensics) checkQCsOnTheSameChain(chain consensus.ChainReader, highestCommittedQCs []utils.QuorumCert, incomingQCandItsParents []utils.QuorumCert) (bool, error) {
	// Re-order two sets of QCs by block Number
	lowerBlockNumQCs := highestCommittedQCs
	higherBlockNumQCs := incomingQCandItsParents
	if incomingQCandItsParents[0].ProposedBlockInfo.Number.Cmp(highestCommittedQCs[0].ProposedBlockInfo.Number) == -1 {
		lowerBlockNumQCs = incomingQCandItsParents
		higherBlockNumQCs = highestCommittedQCs
	}
	// Check whether two sets of QCs are on the same chain(lowerBlockNumQCs & higherBlockNumQCs)
	proposedBlockInfo := higherBlockNumQCs[0].ProposedBlockInfo
	for i := 0; i < int((big.NewInt(0).Sub(higherBlockNumQCs[0].ProposedBlockInfo.Number, lowerBlockNumQCs[0].ProposedBlockInfo.Number)).Int64()); i++ {
		parentHeader := chain.GetHeaderByHash(proposedBlockInfo.Hash)
		var decodedExtraField utils.ExtraFields_v2
		err := utils.DecodeBytesExtraFields(parentHeader.Extra, &decodedExtraField)
		if err != nil {
			log.Error("[ProcessForensics] Fail to decode extra when checking the two QCs set on the same chain", "Error", err)
			return false, err
		}
		proposedBlockInfo = decodedExtraField.QuorumCert.ProposedBlockInfo
	}
	// Check the final proposed blockInfo is the same as what we have from lowerBlockNumQCs[0]
	if reflect.DeepEqual(proposedBlockInfo, lowerBlockNumQCs[0].ProposedBlockInfo) {
		return true, nil
	}

	return false, nil
}

func (f *Forensics) findCommonSigners(currentQc utils.QuorumCert, higherQc utils.QuorumCert) {
}
