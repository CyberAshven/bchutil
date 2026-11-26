// Copyright (c) 2026 The gcash developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"

	"github.com/gcash/bchd/chaincfg/chainhash"
)

// A peer shows what a block's entry tree holds without sending the block: a
// run of consecutive leaves, with the hashes on the run's edges, rebuilds the
// root. The run of leaves whose keys start with a prefix, with the leaf just
// before it and the leaf just after it, also shows that a tree whose leaves
// are in order holds no other leaf with that prefix. A run of one leaf is
// that leaf's branch.
//
// A node answers with a ScriptTree, which builds a block's tree once, and a
// client checks the answer with CheckScriptRange.

var (
	// ErrScriptLeaf is returned for a serialized leaf of the wrong size or
	// of an unknown kind.
	ErrScriptLeaf = errors.New("a script filter leaf is 41 bytes, of kind 0 to 4")

	// ErrScriptPrefix is returned for a key prefix longer than 256 bits, or
	// with a bit set past its length.
	ErrScriptPrefix = errors.New("a key prefix is at most 256 bits, with " +
		"the bits past its length zero")

	// ErrScriptRange is returned when a run of leaves, its neighbours and its
	// edge hashes don't fit a tree of the given leaf count.
	ErrScriptRange = errors.New("the leaves and hashes do not fit the tree")

	// ErrScriptRangeLeaves is returned when the leaves of a range are out of
	// order, a leaf of the run lacks the prefix, or a neighbour has it.
	ErrScriptRangeLeaves = errors.New("the leaves are out of order or do " +
		"not bound the prefix")

	// ErrScriptRangeRoot is returned when the leaves and hashes rebuild
	// another root than the block's.
	ErrScriptRangeRoot = errors.New("the leaves and hashes rebuild another root")
)

// ParseScriptLeaf parses a leaf serialized by ScriptLeaf.Bytes.
func ParseScriptLeaf(b []byte) (ScriptLeaf, error) {
	if len(b) != ScriptLeafSize || b[40] > byte(ScriptLeafTransaction) {
		return ScriptLeaf{}, ErrScriptLeaf
	}
	var leaf ScriptLeaf
	copy(leaf.Key[:], b[:32])
	leaf.TxIndex = binary.LittleEndian.Uint32(b[32:36])
	leaf.Index = binary.LittleEndian.Uint32(b[36:40])
	leaf.Kind = ScriptLeafKind(b[40])
	return leaf, nil
}

// checkScriptPrefix checks that a prefix has at most 256 bits and that the
// bits past its length are zero, so that each prefix has one encoding.
func checkScriptPrefix(prefix *[32]byte, bits uint16) error {
	if bits > 256 {
		return ErrScriptPrefix
	}
	full := int(bits / 8)
	if rem := bits % 8; rem != 0 {
		if prefix[full]&(0xff>>rem) != 0 {
			return ErrScriptPrefix
		}
		full++
	}
	for _, b := range prefix[full:] {
		if b != 0 {
			return ErrScriptPrefix
		}
	}
	return nil
}

// compareScriptPrefix compares the first bits of a key with a prefix.
func compareScriptPrefix(key, prefix *[32]byte, bits uint16) int {
	full := int(bits / 8)
	if c := bytes.Compare(key[:full], prefix[:full]); c != 0 {
		return c
	}
	if rem := bits % 8; rem != 0 {
		k := key[full] & (0xff << (8 - rem))
		switch {
		case k < prefix[full]:
			return -1
		case k > prefix[full]:
			return 1
		}
	}
	return 0
}

// ScriptLeavesWithPrefix returns the run leaves[first:end] of sorted leaves
// whose keys start with the first bits of prefix. A length of 0 takes every
// leaf, and 256 one exact key. When no leaf has the prefix, first equals end,
// the place where such a leaf would sit.
func ScriptLeavesWithPrefix(leaves []ScriptLeaf, prefix *[32]byte, bits uint16) (first, end int, err error) {
	if err := checkScriptPrefix(prefix, bits); err != nil {
		return 0, 0, err
	}
	first = sort.Search(len(leaves), func(i int) bool {
		return compareScriptPrefix(&leaves[i].Key, prefix, bits) >= 0
	})
	end = sort.Search(len(leaves), func(i int) bool {
		return compareScriptPrefix(&leaves[i].Key, prefix, bits) > 0
	})
	return first, end, nil
}

// ScriptTree is a block's entry tree with its levels above the leaves built
// once, so that a node answers every range and branch of the block by reading
// a few hashes for each level, instead of hashing the whole tree again for
// each request. Besides the leaves it holds about one hash for each leaf.
// Nothing changes it after NewScriptTree returns, so goroutines may share
// one.
type ScriptTree struct {
	leaves []ScriptLeaf

	// upper holds the levels above the leaves, from the leaves' parents up
	// to the root. A node without a partner moves up unchanged.
	upper [][]chainhash.Hash
}

// NewScriptTree builds the tree over sorted leaves, as ScriptLeaves returns
// them. The tree keeps leaves, which the caller doesn't change afterwards.
func NewScriptTree(leaves []ScriptLeaf) *ScriptTree {
	t := &ScriptTree{leaves: leaves}
	if len(leaves) < 2 {
		return t
	}
	level := make([]chainhash.Hash, len(leaves))
	for i := range leaves {
		level[i] = ScriptLeafHash(&leaves[i])
	}
	for len(level) > 1 {
		next := make([]chainhash.Hash, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			next = append(next, ScriptNodeHash(&level[i], &level[i+1]))
		}
		t.upper = append(t.upper, next)
		level = next
	}
	return t
}

// Leaves returns the tree's leaves, in order. The caller doesn't change
// them.
func (t *ScriptTree) Leaves() []ScriptLeaf {
	return t.leaves
}

// Root returns the root of the tree, the same that ScriptLeavesRoot gives:
// the zero hash for a tree without leaves.
func (t *ScriptTree) Root() chainhash.Hash {
	switch {
	case len(t.leaves) == 0:
		return chainhash.Hash{}
	case len(t.upper) == 0:
		return ScriptLeafHash(&t.leaves[0])
	default:
		return t.upper[len(t.upper)-1][0]
	}
}

// node returns the node at index of a level of the tree, level 0 being the
// leaves.
func (t *ScriptTree) node(level, index int) chainhash.Hash {
	if level == 0 {
		return ScriptLeafHash(&t.leaves[index])
	}
	return t.upper[level-1][index]
}

// RangeHashes returns the hashes that, with the run of leaves from index lo
// up to end, rebuild the root. Level by level from the leaves up, they are
// the node just left of the run's first node, then the node just right of
// its last node, wherever the run doesn't already reach it. A last node
// without a partner moves up unchanged and needs none.
func (t *ScriptTree) RangeHashes(lo, end int) ([]chainhash.Hash, error) {
	if lo < 0 || lo >= end || end > len(t.leaves) {
		return nil, ErrScriptRange
	}
	var hashes []chainhash.Hash
	a, b, width := lo, end-1, len(t.leaves)
	for level := 0; width > 1; level++ {
		if a%2 == 1 {
			hashes = append(hashes, t.node(level, a-1))
		}
		if b%2 == 0 && b+1 < width {
			hashes = append(hashes, t.node(level, b+1))
		}
		a, b, width = a/2, b/2, (width+1)/2
	}
	return hashes, nil
}

// ScriptRange is a range of a block's entry tree, as a node answers a key
// prefix: the tree's leaf count, the run of leaves whose keys start with the
// prefix and the index of its first leaf, the leaves just before and just
// after the run where the tree has them, and the hashes that rebuild the
// root with those leaves.
type ScriptRange struct {
	Count  uint32
	First  uint32
	Run    []ScriptLeaf
	Before *ScriptLeaf
	After  *ScriptLeaf
	Hashes []chainhash.Hash
}

// Range returns the range of the tree for the keys that start with the first
// bits of prefix. When no leaf has the prefix, the run is empty and First is
// the place where such a leaf would sit. The range's leaves are the tree's
// own, which the caller doesn't change.
func (t *ScriptTree) Range(prefix *[32]byte, bits uint16) (*ScriptRange, error) {
	first, end, err := ScriptLeavesWithPrefix(t.leaves, prefix, bits)
	if err != nil {
		return nil, err
	}
	r := &ScriptRange{
		Count: uint32(len(t.leaves)),
		First: uint32(first),
		Run:   t.leaves[first:end:end],
	}
	lo, hi := first, end
	if first > 0 {
		r.Before = &t.leaves[first-1]
		lo--
	}
	if end < len(t.leaves) {
		r.After = &t.leaves[end]
		hi++
	}
	if lo < hi {
		if r.Hashes, err = t.RangeHashes(lo, hi); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Check checks the range against the root in front of the block's script
// filter, with CheckScriptRange.
func (r *ScriptRange) Check(root chainhash.Hash, prefix *[32]byte, bits uint16) error {
	return CheckScriptRange(root, r.Count, r.First, r.Run, r.Before, r.After, r.Hashes, prefix, bits)
}

// ScriptRangeHashes returns the hashes that, with the run leaves[lo:end],
// rebuild the root of the tree over leaves, as ScriptTree.RangeHashes does.
// It builds the tree for this one run: a node that answers several runs of a
// block keeps a ScriptTree instead.
func ScriptRangeHashes(leaves []ScriptLeaf, lo, end int) ([]chainhash.Hash, error) {
	if lo < 0 || lo >= end || end > len(leaves) {
		return nil, ErrScriptRange
	}
	return NewScriptTree(leaves).RangeHashes(lo, end)
}

// ScriptRangeRoot rebuilds the root of a tree of count leaves from a run of
// consecutive leaves that starts at index lo and the hashes ScriptRangeHashes
// lists for it. It fails when the hashes are too few or too many.
func ScriptRangeRoot(count, lo uint32, run []ScriptLeaf, hashes []chainhash.Hash) (chainhash.Hash, error) {
	if len(run) == 0 || uint64(lo)+uint64(len(run)) > uint64(count) {
		return chainhash.Hash{}, ErrScriptRange
	}
	nodes := make([]chainhash.Hash, len(run))
	for i := range run {
		nodes[i] = ScriptLeafHash(&run[i])
	}
	a, b, width := uint64(lo), uint64(lo)+uint64(len(run))-1, uint64(count)
	for width > 1 {
		if a%2 == 1 {
			if len(hashes) == 0 {
				return chainhash.Hash{}, ErrScriptRange
			}
			nodes = append([]chainhash.Hash{hashes[0]}, nodes...)
			hashes = hashes[1:]
			a--
		}
		if b%2 == 0 && b+1 < width {
			if len(hashes) == 0 {
				return chainhash.Hash{}, ErrScriptRange
			}
			nodes = append(nodes, hashes[0])
			hashes = hashes[1:]
			b++
		}
		nodes = scriptNextLevel(nodes)
		a, b, width = a/2, b/2, (width+1)/2
	}
	if len(hashes) != 0 {
		return chainhash.Hash{}, ErrScriptRange
	}
	return nodes[0], nil
}

// CheckScriptRange checks a range of a block's entry tree against the root in
// front of the block's script filter. The tree has count leaves, and run is
// the run of them from index first whose keys start with the prefix. before
// and after are the leaves next to the run: before is given exactly when first
// is above 0, and after exactly when the run ends before the last leaf. When
// it returns nil, a tree whose leaves are in order holds no other leaf with
// the prefix. The leaves the reply doesn't show are not checked here. A tree
// with leaves out of order is not the one the block gives, and has another
// root.
//
// The count and the first index are the peer's word, but a wrong one doesn't
// let it hide a leaf. A leaf's hash can't pass for an inner node's, since the
// two are hashed with different tags, so leaves and hashes that rebuild the
// root follow the real tree's shape whatever count they claim. The hashes a
// reply supplies sit outside its leaves, never between two of them, so its
// leaves are consecutive leaves of the tree. A leaf it gives as the first,
// with no leaf before it, sits on the path that goes left at every level, so
// it is the tree's first leaf, and a leaf it gives as the last, with no leaf
// after it, sits on the path that goes right at every level, so it is the
// tree's last. A reply that claims fewer leaves than the tree has, so as to
// drop its last leaves, therefore rebuilds another root.
//
// The check is of where the leaves sit and which keys they have, not of what
// a key stands for. A token category's or a transaction's key can also be a
// script's key (see ScriptKey), so the run for TxidKey(t) can hold a
// ScriptLeafOutput leaf of an output whose script is 0x02 || t. A caller
// checks each leaf's Kind: a client that looks a transaction up takes it as
// confirmed only from the leaf ScriptTxidLeaf finds, and a non-empty run
// says nothing by itself.
//
// ErrScriptRangeRoot means the reply doesn't belong to that root.
// ErrScriptRangeLeaves means the leaves do rebuild the root, so they are the
// tree's own, but are out of order or don't bound the prefix: the peer serves
// a wrong tree or a wrong answer.
func CheckScriptRange(root chainhash.Hash, count, first uint32, run []ScriptLeaf,
	before, after *ScriptLeaf, hashes []chainhash.Hash, prefix *[32]byte, bits uint16) error {

	if err := checkScriptPrefix(prefix, bits); err != nil {
		return err
	}
	end := uint64(first) + uint64(len(run))
	if end > uint64(count) || (first > 0) != (before != nil) || (end < uint64(count)) != (after != nil) {
		return ErrScriptRange
	}
	if count == 0 {
		if len(hashes) != 0 {
			return ErrScriptRange
		}
		if root != (chainhash.Hash{}) {
			return ErrScriptRangeRoot
		}
		return nil
	}

	span := make([]ScriptLeaf, 0, len(run)+2)
	lo := first
	if before != nil {
		span = append(span, *before)
		lo--
	}
	span = append(span, run...)
	if after != nil {
		span = append(span, *after)
	}
	rebuilt, err := ScriptRangeRoot(count, lo, span, hashes)
	if err != nil {
		return err
	}
	if rebuilt != root {
		return ErrScriptRangeRoot
	}

	for i := range run {
		if compareScriptPrefix(&run[i].Key, prefix, bits) != 0 {
			return ErrScriptRangeLeaves
		}
	}
	if before != nil && compareScriptPrefix(&before.Key, prefix, bits) >= 0 {
		return ErrScriptRangeLeaves
	}
	if after != nil && compareScriptPrefix(&after.Key, prefix, bits) <= 0 {
		return ErrScriptRangeLeaves
	}
	for i := 1; i < len(span); i++ {
		if compareScriptLeaves(span[i-1], span[i]) >= 0 {
			return ErrScriptRangeLeaves
		}
	}
	return nil
}

// ScriptTxidLeaf returns the leaf of a transaction's own ID among the leaves
// of a run: the leaf of kind ScriptLeafTransaction whose key is
// TxidKey(txid). It reports false when the run has none. The run for that
// key can also hold leaves of other kinds, an output whose script is
// 0x02 || txid for one (see ScriptKey), and those say nothing of the
// transaction.
func ScriptTxidLeaf(run []ScriptLeaf, txid chainhash.Hash) (ScriptLeaf, bool) {
	key := TxidKey(txid)
	for _, leaf := range run {
		if leaf.Kind == ScriptLeafTransaction && leaf.Key == key {
			return leaf, true
		}
	}
	return ScriptLeaf{}, false
}
