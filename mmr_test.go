package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeightBitmapForMMRSize(t *testing.T) {
	testValues := []struct {
		mmrSize  uint64
		expected uint64
	}{
		{1, 1},
		{3, 2},
		{4, 3},
		{7, 4},
		{10, 6},
		{15, 8},
		{22, 12},
		{25, 14},
		{26, 15},
		{31, 16},
		{32, 17},
		{34, 18},
		{35, 19},
		{38, 20},
		{41, 22},
		{42, 23},
	}

	for _, test := range testValues {
		peaks, _ := HeightBitmapForMMRSize(test.mmrSize)
		if peaks != test.expected {
			fmt.Printf("HeightBitmapForMMRSize(%d) = %d, want %d", test.mmrSize, peaks, test.expected)
		}
	}
}

func TestMMRAddLeaf(t *testing.T) {
	testCases := []struct {
		nrLeavesToAdd      int
		expectedNrElements int
	}{
		{7, 11},
		{8, 15},
		{9, 16},
		{10, 18},
		{16, 31},
	}

	for _, tc := range testCases {
		mmr := New(sha256.New())

		for i := 0; i < tc.nrLeavesToAdd; i++ {
			leaf := []byte{byte(rand.Intn(256))}
			mmr.AddLeaf(leaf)
		}

		if len(mmr.elements) != tc.expectedNrElements {
			t.Errorf("After adding %d leaves, expected %d elements in MMR, got %d", tc.nrLeavesToAdd, tc.expectedNrElements, len(mmr.elements))
		}
	}
}

func (m *MMR) toString() string {
	var buffer bytes.Buffer

	buffer.WriteString("MMR:\n")
	for i, element := range m.elements {
		buffer.WriteString(fmt.Sprintf("Element %d: %s\n", i, hex.EncodeToString(element)))
	}

	hashStr := ""
	if m.hash != nil {
		hashStr = fmt.Sprintf("%x", m.hash.Sum(nil))
	}
	buffer.WriteString(fmt.Sprintf("Hash: %s\n", hashStr))

	return buffer.String()
}

func (m *MMRProof) toString() string {
	var buffer bytes.Buffer

	buffer.WriteString("MMRProof:\n")
	buffer.WriteString("MerkleProof:\n")
	for i, element := range m.MerkleProof {
		side := "Right"
		if element.IsLeft {
			side = "Left"
		}
		buffer.WriteString(fmt.Sprintf("  Element %d: Hash: %s, Side: %s\n", i, hex.EncodeToString(element.Hash), side))
	}

	buffer.WriteString("Peaks:\n")
	for i, peak := range m.Peaks {
		buffer.WriteString(fmt.Sprintf("  Peak %d: %s\n", i, hex.EncodeToString(peak)))
	}

	hashStr := ""
	if m.Hash != nil {
		hashStr = fmt.Sprintf("%x", m.Hash.Sum(nil))
	}
	buffer.WriteString(fmt.Sprintf("Hash: %s\n", hashStr))

	return buffer.String()
}

func TestGetProof(t *testing.T) {
	assert := assert.New(t)
	nrLeaves := 16

	hashFunc := sha256.New()
	mmr := New(hashFunc)
	var leaves [][]byte

	for i := 0; i < nrLeaves; i++ {
		leaf := []byte{byte(rand.Intn(256))}
		leaves = append(leaves, leaf)
		mmr.AddLeaf(leaf)
	}
	// t.Logf("mmr: %v\n", mmr.toString())

	// Test 1
	// standardIndex := 8
	// leafIndex := 15
	// Test 2
	// standardIndex := 4
	// leafIndex := 7
	// Test 3
	standardIndex := 0
	leafIndex := 0

	proof := mmr.GetProof(uint64(leafIndex))
	// t.Logf("Proof: %v\n", proof.toString())

	root := mmr.BaggingThePeaks(sha256.New())                           // Assuming BaggingThePeaks is implemented
	verified := proof.Verify(leaves[standardIndex], root, sha256.New()) // Assuming Verify method is implemented
	// t.Logf("Verified: %v\n", verified)
	assert.True((verified))
}
