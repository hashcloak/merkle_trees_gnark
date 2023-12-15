package main

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func fill32Bytes(leaf *big.Int) []byte {
	var b [32]byte
	leafBytes := leaf.Bytes()
	copy(b[32-len(leafBytes):], leafBytes)
	return b[:]
}

func TestSimpleMMR(t *testing.T) {
	assert := test.NewAssert(t)
	nrLeaves := 17
	var leaves [][]byte
	mod := ecc.BN254.ScalarField()

	mmr := New(hash.MIMC_BN254.New())
	for i := 0; i < nrLeaves; i++ {
		leaf, err := rand.Int(rand.Reader, mod)
		assert.NoError(err)
		// make sure each leaf has 32 bytes
		b := fill32Bytes(leaf)
		leaves = append(leaves, b)
		mmr.AddLeaf(b)
	}

	// standardIndex := 8
	// leafIndex := 15
	standardIndex := 4
	leafIndex := 7
	// standardIndex := 0
	// leafIndex := 0

	proof := mmr.GetProof(uint64(leafIndex))
	root := mmr.BaggingThePeaks(hash.MIMC_BN254.New())
	verified := proof.Verify(leaves[standardIndex], root, hash.MIMC_BN254.New())
	// Check the proof is correct in normal Golang
	assert.True((verified))

	// Check proof in circuit
	var mmrCircuit MMRCircuit
	var witness MMRCircuit
	depth := len(proof.MerkleProof)
	nrPeaks := len(proof.Peaks)
	mmrCircuit.ProofElements = make([]ProofElm, depth)
	mmrCircuit.Peaks = make([]frontend.Variable, nrPeaks)
	// Fill witness
	witness.ProofElements = make([]ProofElm, depth)
	witness.Peaks = make([]frontend.Variable, nrPeaks)
	for i := 0; i < depth; i++ {
		witness.ProofElements[i].Val = proof.MerkleProof[i].Hash

		if proof.MerkleProof[i].IsLeft {
			witness.ProofElements[i].IsLeft = big.NewInt(1)
		} else {
			witness.ProofElements[i].IsLeft = big.NewInt(0)
		}

	}

	for i := 0; i < nrPeaks; i++ {
		witness.Peaks[i] = proof.Peaks[i]
	}

	witness.Root = root
	witness.Leaf = leaves[standardIndex]

	// PROVER SUCCESS CASE
	// Check circuit with valid witness
	assert.ProverSucceeded(&mmrCircuit, &witness, test.WithCurves(ecc.BN254))

	// PROVER FAIL CASES
	// With the wrong leaf, the prover should fail
	witness.Leaf = leaves[0]
	assert.ProverFailed(&mmrCircuit, &witness, test.WithCurves(ecc.BN254))

	// With the wrong root, the prover should fail, first make sure the leaf is reset correctly
	witness.Leaf = leaves[standardIndex]
	assert.ProverSucceeded(&mmrCircuit, &witness, test.WithCurves(ecc.BN254))
	witness.Root = leaves[standardIndex]
	assert.ProverFailed(&mmrCircuit, &witness, test.WithCurves(ecc.BN254))

	// With a wrong peak, the prover should fail, first make sure the root is reset correctly
	witness.Root = root
	assert.ProverSucceeded(&mmrCircuit, &witness, test.WithCurves(ecc.BN254))
	witness.Peaks[0] = leaves[standardIndex]
	assert.ProverFailed(&mmrCircuit, &witness, test.WithCurves(ecc.BN254))

	// With a wrong merkle proof, the prover should fail, first make sure the peak is reset correctly
	witness.Peaks[0] = proof.Peaks[0]
	assert.ProverSucceeded(&mmrCircuit, &witness, test.WithCurves(ecc.BN254))
	if proof.MerkleProof[0].IsLeft {
		witness.ProofElements[0].IsLeft = big.NewInt(0)
	} else {
		witness.ProofElements[0].IsLeft = big.NewInt(1)
	}
	assert.ProverFailed(&mmrCircuit, &witness, test.WithCurves(ecc.BN254))

}
