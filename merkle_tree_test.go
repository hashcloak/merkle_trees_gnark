package main

import (
	"bytes"
	"crypto/rand"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestSimpleMerkleTree(t *testing.T) {
	assert := test.NewAssert(t)
	mod := ecc.BN254.ScalarField()
	modNbBytes := len(mod.Bytes())

	// Create a Merkle Proof to test with
	hasher := hash.MIMC_BN254
	hGo := hasher.New()
	nrLeaves := 32
	proofIndex := uint64(0)
	var l []byte
	depth := 5

	var buf bytes.Buffer
	for i := 0; i < nrLeaves; i++ {
		leaf, err := rand.Int(rand.Reader, mod)
		assert.NoError(err)
		b := leaf.Bytes()
		if i == int(proofIndex) {
			l = b
		}
		buf.Write(make([]byte, modNbBytes-len(b)))
		buf.Write(b)
	}
	// Create proof
	merkleRoot, proofPath, numLeaves, err := merkletree.BuildReaderProof(&buf, hGo, nrLeaves, proofIndex)
	if err != nil {
		t.Fatal("error creating Merkle Proof")
	}
	// Check proof
	verified := merkletree.VerifyProof(hGo, merkleRoot, proofPath, proofIndex, numLeaves)
	if !verified {
		t.Fatal("The created Merkle Proof is not valid")
	}

	// Check proof in circuit
	var mtCircuit MTCircuit
	var witness MTCircuit
	mtCircuit.ProofElements = make([]frontend.Variable, depth)
	witness.ProofElements = make([]frontend.Variable, depth)
	// skip elm 0 (in proofPath) since it's the leaf hash and we calculate it ourselves
	for i := 0; i < depth; i++ {
		witness.ProofElements[i] = proofPath[i+1]
	}
	witness.ProofIndex = proofIndex
	witness.Root = merkleRoot
	witness.Leaf = l

	assert.ProverSucceeded(&mtCircuit, &witness, test.WithCurves(ecc.BN254))
}
