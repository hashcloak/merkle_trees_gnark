# Merkle Tree functionality using gnark

This repository implements Merkle Proof and Merkle Mountain Ranges Proof verification using
[gnark](https://github.com/Consensys/gnark/tree/master). It includes 2 circuits designed to verify the validity of a proof for either of the structures. 

Merkle Tree: circuit in `merkle_tree.go` and test in `merkle_tree_test.go`.

MMR: standard Go functionality in `mmr.go`, this is an adaptation of [this](https://github.com/hashcloak/plonky2-merkle-trees/blob/master/src/mmr/merkle_mountain_ranges.rs) Rust implementation. Circuit implementation and accompanying test in `mmr_circuit.go` and `mmr_circuit_test.go` respectively. 

## Run

This runs the `main` function in `main.go`. (Currently empty)

```
go mod tidy
go run  .
```

## Run tests

This runs all tests in the files ending with `_test.go`. 

```
go test
```

## Gnark Resources 

Gnark: https://github.com/Consensys/gnark/

Gnark-crypto: https://github.com/Consensys/gnark-crypto

### Introduction blog

Read the introduction blog [here](https://consensys.io/blog/gnark-your-guide-to-write-zksnarks-in-go).

### Circuit Frontend API

Functionality available for circuit design, reference [here](https://github.com/Consensys/gnark/blob/master/frontend/api.go).
