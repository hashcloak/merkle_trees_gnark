package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Circuit that checks an MMR Proof

type ProofElm struct {
	Val    frontend.Variable
	IsLeft frontend.Variable
}

type MMRCircuit struct {
	Root          frontend.Variable `gnark:",public"`
	ProofElements []ProofElm
	Peaks         []frontend.Variable
	Leaf          frontend.Variable
}

func (circuit *MMRCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Hash leaf
	h.Reset()
	h.Write(circuit.Leaf)
	hashed := h.Sum()

	// (1) Check Merkle (subtree) Proof
	for i := 0; i < len(circuit.ProofElements); i++ {
		element := circuit.ProofElements[i].Val
		isLeft := circuit.ProofElements[i].IsLeft
		d1 := api.Select(isLeft, element, hashed)
		d2 := api.Select(isLeft, hashed, element)

		h.Reset()
		h.Write(d1, d2)
		hashed = h.Sum()
	}

	// (2) Check that the resulting hash is among the peaks in the proof
	mul := api.Cmp(circuit.Peaks[0], hashed)

	for i := 1; i < len(circuit.Peaks); i++ {
		temp := api.Cmp(circuit.Peaks[i], hashed)

		mul = api.Mul(mul, temp)
	}

	// If any of the peaks was equal to the hash, this should be 0

	// if mul == 0, then mul and -mul are equal
	minusMul := api.Neg(mul)
	// minusCheck := api.Neg(check)
	api.AssertIsEqual(mul, minusMul)

	// (3) Hash all the peaks together
	h.Reset()
	for i := 0; i < len(circuit.Peaks); i++ {
		h.Write(circuit.Peaks[i])
	}
	calculatedRoot := h.Sum()

	// (4) Compare result to MMR root
	api.AssertIsEqual(calculatedRoot, circuit.Root)

	return nil
}
