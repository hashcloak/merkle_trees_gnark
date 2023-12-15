package main

import (
	"bytes"
	"hash"
	"math"
	"math/bits"
)

// Using MMR implementation from https://github.com/hashcloak/plonky2-merkle-trees/blob/master/src/mmr/merkle_mountain_ranges.rs
type MMR struct {
	// each elements is a hash
	elements [][]byte
	hash     hash.Hash
}

type MMRProof struct {
	MerkleProof []ProofElement
	Peaks       [][]byte
	Hash        hash.Hash
}

// A single element of the Merkle Proof
type ProofElement struct {
	Hash   []byte
	IsLeft bool
}

func New(h hash.Hash) *MMR {
	return &MMR{
		make([][]byte, 0),
		h,
	}
}

// Return a number whose bits represent at what heights there are peaks + the height of the next element to be added
// There is always at most 1 peak at each height, because if there are multiple, they get hashed together to a new peak
// A bit set in a position means there is a peak there. Counting starts from the right at height 0.
// Examples:
// In: 1. Out: 1: peak at height 0
// In: 4. Out: 11 : peaks at height 1 and 0
// In: 11. Out: 111 : peaks at heights 2,1 and 0
// In: 25. Out: 1110 : peaks at heights 3,2 and 1
func HeightBitmapForMMRSize(size uint64) (uint64, uint64) {
	// No peaks and next element will have height 0
	if size == 0 {
		return 0, 0
	}

	var allPeaksSet uint64
	allPeaksSet = math.MaxUint64 >> bits.LeadingZeros64(size)

	// For each peak holds:
	// If peak is at height x, the nr of elements of that subtree is 2^{x+1}-1 = 2ˆx+2ˆ{x-1}+..+2ˆ1+1 This equals a number with x+1 bits set to 1
	// For example, if peak is at height 4:
	// 2^5-1=31 (equals 2^4+2^3+2^2+2ˆ1+1=31) In bits 11111

	// Now, iterate over each peak (bit) to see whether it's set or not
	// To decide if a peak is included, we check how many elements "fit" in the mmr_size
	// Example mmr_size 25. Then 31, 15, 7 and 3 are the size of the subtrees of heights 4,3,2 and 1 resp.
	// 25 >= 31 NO
	// 25 >= 15 YES set bit 1000
	// 10 >= 7 YES set bit 100
	// 3 >= 3 YES set bit 10
	// 0
	// Result 1110

	var subtreeSize = allPeaksSet
	var updatedMmrSize = size
	// We'll set the actual peaks here
	var peaks uint64 = 0

	for subtreeSize > 0 {

		peaks <<= 1
		if updatedMmrSize >= subtreeSize {
			peaks |= 1
			updatedMmrSize -= subtreeSize
		}
		subtreeSize >>= 1
	}

	return peaks, updatedMmrSize
}

// add a (non-hashed) leaf to the MMR
// this possibly leads to more updates to the MMR, depending on its current form
func (mmr *MMR) AddLeaf(leaf []byte) {
	mmr.hash.Reset()
	_, err := mmr.hash.Write(leaf)
	if err != nil {
		panic(err)
	}
	hashedLeaf := mmr.hash.Sum(nil)

	if len(mmr.elements) == 0 {
		mmr.elements = append(mmr.elements, hashedLeaf)
		return
	}

	// Add new peaks as long as needed:
	//   Reading from right to left; add a new peak if there was a peak at the position
	//   Once there's a gap of peaks we stop, because it means next up is a separate previous subtree
	// Get inital peaks map based on mmr_size before adding new leaf
	peaks, _ := HeightBitmapForMMRSize(uint64(len(mmr.elements)))
	var currentPos = uint64(len(mmr.elements))
	mmr.elements = append(mmr.elements, hashedLeaf)
	var nextHash = hashedLeaf
	var height = 1
	for peaks > 0 {
		if peaks&1 == 1 {
			prevPeakIndex := currentPos - ((1 << height) - 1)
			prevPeak := mmr.elements[prevPeakIndex]
			mmr.hash.Reset()
			mmr.hash.Write(prevPeak)
			mmr.hash.Write(nextHash)
			nextHash = mmr.hash.Sum(nil)
			mmr.elements = append(mmr.elements, nextHash)
		} else {
			break
		}
		peaks >>= 1
		height++
		currentPos++
	}

}

// addRightElm adds a proof element to the MMR proof, that should be hashed on the right side.
// It returns an updated slice of ProofElements, the nextIndex and a boolean indicating whether we're still operating within the tree.
func addRightElm(currIndex uint64, height uint32, mmr *MMR, proofElms []ProofElement) ([]ProofElement, uint64, bool) {
	nextElmIndex := currIndex + (1<<(height+1) - 1)
	if nextElmIndex < uint64(len(mmr.elements)-1) {
		proofElms = append(proofElms, ProofElement{
			Hash:   mmr.elements[nextElmIndex],
			IsLeft: false,
		})
		return proofElms, nextElmIndex + 1, true
	}
	// the index doesn't change any further, intree = false so it will stop after this
	return proofElms, currIndex, false
}

// returns Merkle Proof for the element with given mmrIndex wrt the subtree it is in
func (mmr *MMR) GetSubtreeProofElm(mmrIndex uint64) []ProofElement {
	var proofElms []ProofElement
	currIndex := mmrIndex
	inTree := true
	height := uint32(0)

	for inTree {
		if currIndex >= ((1 << (height + 1)) - 1) {
			prevElmIndex := currIndex - ((1 << (height + 1)) - 1)
			_, heightPrevElm := HeightBitmapForMMRSize(prevElmIndex)
			if heightPrevElm == uint64(height) {
				proofElms = append(proofElms, ProofElement{Hash: mmr.elements[prevElmIndex], IsLeft: true})
				currIndex++
			} else {
				proofElms, currIndex, inTree = addRightElm(currIndex, height, mmr, proofElms)
			}
		} else {
			proofElms, currIndex, inTree = addRightElm(currIndex, height, mmr, proofElms)
		}
		height++
	}
	return proofElms
}

// returns all peaks of the MMR
func (mmr *MMR) GetPeaks() [][]byte {
	var peaks [][]byte
	mmrLen := len(mmr.elements)

	// Try to fit in peaks until we get to the current position
	maxTreeSize := uint64(math.MaxUint64 >> bits.LeadingZeros64(uint64(mmrLen)))
	currentIndex := uint64(mmrLen)
	var peakPos uint64 = 0

	for maxTreeSize > 0 {
		if currentIndex >= maxTreeSize {
			peakPos += maxTreeSize

			if peakPos-1 < uint64(len(mmr.elements)) {
				peaks = append(peaks, mmr.elements[peakPos-1])
			}
			currentIndex -= maxTreeSize
		}

		maxTreeSize >>= 1
	}

	return peaks
}

// returns an MMRProof for leaf with given (mmr) index
// mmr index is the index wrt all MMR elements
func (mmr *MMR) GetProof(mmrIndex uint64) MMRProof {
	// 1. Get the Merkle proof
	path := mmr.GetSubtreeProofElm(mmrIndex)

	// 2. Get the peaks
	peaks := mmr.GetPeaks()

	return MMRProof{
		MerkleProof: path,
		Peaks:       peaks,
		Hash:        mmr.hash,
	}
}

// hashes all peaks together
// this operation is called "Bagging the peaks"
func (mmr *MMR) BaggingThePeaks(h hash.Hash) []byte {
	peaks := mmr.GetPeaks()

	h.Reset()
	for _, peak := range peaks {
		h.Write(peak)
	}
	root := h.Sum(nil)

	return root
}

// returns whether the MMR proof is valid wrt the given leaf and MMR root
// Checks:
// - Merkle proof for leaf checks out
// - the root of subtree is among peaks
// - hashing all roots together should give the root
func (proof MMRProof) Verify(leaf []byte, root []byte, h hash.Hash) bool {
	// Reset and hash the leaf
	h.Reset()
	h.Write(leaf)
	leafHash := h.Sum(nil)

	// 1. Check Merkle proof of subtree
	nextHash := leafHash
	for _, elem := range proof.MerkleProof {
		h.Reset()

		if elem.IsLeft {
			h.Write(elem.Hash)
			h.Write(nextHash)
		} else {
			h.Write(nextHash)
			h.Write(elem.Hash)
		}
		nextHash = h.Sum(nil)
	}

	// 2. Check this hash is among the peaks
	found := false
	for _, peak := range proof.Peaks {
		if bytes.Equal(nextHash, peak) {
			found = true
			break
		}
	}
	if !found {
		return false
	}

	// 3. Hash all peaks together
	h.Reset()
	for _, peak := range proof.Peaks {
		_, _ = h.Write(peak)
	}
	calcRoot := h.Sum(nil)

	// 4. Compare calculated root with provided root
	isEqualRoot := bytes.Equal(calcRoot, root)

	return isEqualRoot
}
