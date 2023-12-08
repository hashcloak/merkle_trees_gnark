package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Circuit that checks a Merkle Proof
// This is a variation of the existing circuit in the gnark library https://github.com/Consensys/gnark/blob/master/std/accumulator/merkle/verify.go

type MTCircuit struct {
	Root          frontend.Variable   `gnark:",public"`
	ProofElements []frontend.Variable // private
	ProofIndex    frontend.Variable   // private
	Leaf          frontend.Variable   // private
}

func (circuit *MTCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Hash leaf
	h.Reset()
	h.Write(circuit.Leaf)
	hashed := h.Sum()

	depth := len(circuit.ProofElements)
	proofIndices := api.ToBinary(circuit.ProofIndex, depth)

	// Continuously hash with the proof elements
	for i := 0; i < len(circuit.ProofElements); i++ {
		element := circuit.ProofElements[i]
		// 0 = left, 1 = right
		index := proofIndices[i]

		d1 := api.Select(index, element, hashed)
		d2 := api.Select(index, hashed, element)

		h.Reset()
		h.Write(d1, d2)
		hashed = h.Sum()
	}

	// Verify calculates hash is equal to root
	api.AssertIsEqual(hashed, circuit.Root)
	return nil
}
