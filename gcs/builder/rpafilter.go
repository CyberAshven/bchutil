// Copyright (c) 2026 The gcash developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"
	"slices"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
)

// The input prefix filter (filter type 2) lets a wallet that receives on a
// reusable payment address find the blocks that may pay it without telling
// anyone the prefix it looks for. A sender grinds one input among the first
// 30 of a transaction until the first bits of the double SHA-256 of that
// serialized input equal bits of the receiver's scan key, so a block may pay
// the wallet exactly when one of those inputs has the wallet's prefix.
//
// The filter is the set of the first two bytes of the double SHA-256 of each
// of the first 30 inputs of every transaction of the block but the coinbase,
// as 16-bit values, sorted and each kept once. Its count comes first, then a
// byte that follows from the count alone and says how the values are coded:
// Rice coded gaps with that byte as the parameter, or, for 19,197 values and
// more, a bitmap of every 16-bit value. So every node gives the same bytes. It
// is built from the block alone.

const (
	// RPAFilterInputs is how many of a transaction's first inputs the input
	// prefix filter takes.
	RPAFilterInputs = 30

	// RPAFilterMaxValues is the most values an input prefix filter can
	// hold: every 16-bit value.
	RPAFilterMaxValues = 1 << 16

	// RPAFilterBitmap is the byte after the count of a filter whose values
	// are a bitmap rather than Rice coded.
	RPAFilterBitmap = 16

	// RPAFilterBitmapFrom is the smallest count whose filter is a bitmap.
	// From there on every Rice parameter takes more bits than the bitmap's
	// 65,536 for values drawn at random.
	RPAFilterBitmapFrom = 19197

	// rpaFilterBitmapBytes is the size of a bitmap of every 16-bit value.
	rpaFilterBitmapBytes = RPAFilterMaxValues / 8
)

// rpaFilterKFrom holds, for each Rice parameter k from 1 to 15 at index k,
// the smallest count that takes it. A count takes the smallest k whose start
// is not above it. Each k is the one that codes that many distinct values
// drawn at random in the fewest bits on average, worked out exactly from the
// distribution of their gaps, the first gap from 0. At the one tie, one
// value, where k = 14 and k = 15 both take 16.5 bits, the larger k is taken.
// No count takes k = 0: from 19,197 values on the bitmap is smaller.
var rpaFilterKFrom = [16]int{
	0, 18055, 8356, 4051, 1997, 992, 494, 246, 123, 61, 30, 15, 7, 3, 2, 1,
}

var (
	// ErrRPAFilterTruncated is returned for filter bytes that end before
	// the count, the coding byte or the values they promise.
	ErrRPAFilterTruncated = errors.New("input prefix filter ends early")

	// ErrRPAFilterCount is returned for a count not in its shortest
	// CompactSize form, or above 65,536.
	ErrRPAFilterCount = errors.New("input prefix filter count is not in its " +
		"shortest form or is above 65,536")

	// ErrRPAFilterK is returned for a coding byte, a Rice parameter or the
	// bitmap's, other than the one the count gives, so that a set of values
	// has one encoding.
	ErrRPAFilterK = errors.New("input prefix filter parameter is not the one " +
		"its count gives")

	// ErrRPAFilterGap is returned for a gap of 0 after the first value: a
	// value repeated, which the set holds once.
	ErrRPAFilterGap = errors.New("input prefix filter repeats a value")

	// ErrRPAFilterValue is returned for a value above 65,535.
	ErrRPAFilterValue = errors.New("input prefix filter value is above 65,535")

	// ErrRPAFilterBitmapCount is returned for a bitmap that holds another
	// number of values than the filter's count.
	ErrRPAFilterBitmapCount = errors.New("input prefix filter bitmap holds " +
		"another number of values than its count")

	// ErrRPAFilterPadding is returned for a set bit after the last value.
	ErrRPAFilterPadding = errors.New("input prefix filter padding is not zero")

	// ErrRPAFilterTrailing is returned for bytes after the last value's.
	ErrRPAFilterTrailing = errors.New("input prefix filter has trailing bytes")

	// ErrRPAFilterValues is returned by EncodeRPAFilter for values that are
	// not sorted or not distinct.
	ErrRPAFilterValues = errors.New("input prefix filter values are not " +
		"sorted and distinct")
)

// RPAInputValue returns the value of an input in the input prefix filter: the
// first two bytes, big-endian, of the double SHA-256 of the input as it is
// serialized in its transaction.
func RPAInputValue(txIn *wire.TxIn) uint16 {
	var b bytes.Buffer
	b.Grow(chainhash.HashSize + 4 + wire.MaxVarIntPayload + len(txIn.SignatureScript) + 4)
	b.Write(txIn.PreviousOutPoint.Hash[:])
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], txIn.PreviousOutPoint.Index)
	b.Write(u32[:])
	// Writing to a bytes.Buffer doesn't fail.
	_ = wire.WriteVarInt(&b, 0, uint64(len(txIn.SignatureScript)))
	b.Write(txIn.SignatureScript)
	binary.LittleEndian.PutUint32(u32[:], txIn.Sequence)
	b.Write(u32[:])
	h := chainhash.DoubleHashB(b.Bytes())
	return uint16(h[0])<<8 | uint16(h[1])
}

// RPAValues returns the values of the input prefix filter of transactions
// none of which is a coinbase: those of the first 30 inputs of each, sorted,
// each once.
func RPAValues(txs []*wire.MsgTx) []uint16 {
	var seen [RPAFilterMaxValues / 64]uint64
	n := 0
	for _, tx := range txs {
		ins := tx.TxIn
		if len(ins) > RPAFilterInputs {
			ins = ins[:RPAFilterInputs]
		}
		for _, txIn := range ins {
			v := RPAInputValue(txIn)
			if seen[v/64]&(1<<(v%64)) == 0 {
				seen[v/64] |= 1 << (v % 64)
				n++
			}
		}
	}
	values := make([]uint16, 0, n)
	for i, word := range seen {
		for word != 0 {
			b := bits.TrailingZeros64(word)
			values = append(values, uint16(i*64+b))
			word &= word - 1
		}
	}
	return values
}

// RPABlockValues returns the values of a block's input prefix filter: those
// of every transaction but the coinbase.
func RPABlockValues(block *wire.MsgBlock) []uint16 {
	if len(block.Transactions) < 2 {
		return nil
	}
	return RPAValues(block.Transactions[1:])
}

// RPAFilterK returns the coding byte of a filter of n values, the byte after
// its count: RPAFilterBitmap for RPAFilterBitmapFrom values or more, and
// otherwise the Rice parameter, 1 to 15, from the counts where each starts.
// Only a count from 1 to 65,536 has one, since a filter without values has no
// coding byte. For any other n it returns 0, which no filter takes.
func RPAFilterK(n int) uint8 {
	switch {
	case n < 1 || n > RPAFilterMaxValues:
		return 0
	case n >= RPAFilterBitmapFrom:
		return RPAFilterBitmap
	}
	for k := 1; ; k++ {
		if n >= rpaFilterKFrom[k] {
			return uint8(k)
		}
	}
}

// rpaBitWriter packs bits most significant first.
type rpaBitWriter struct {
	out  []byte
	cur  byte
	used uint
}

func (w *rpaBitWriter) bit(one bool) {
	if one {
		w.cur |= 0x80 >> w.used
	}
	w.used++
	if w.used == 8 {
		w.out = append(w.out, w.cur)
		w.cur, w.used = 0, 0
	}
}

func (w *rpaBitWriter) flush() []byte {
	if w.used > 0 {
		w.out = append(w.out, w.cur)
	}
	return w.out
}

// EncodeRPAFilter encodes the values of an input prefix filter: their count
// as CompactSize, then, when there are any, the coding byte RPAFilterK gives
// for the count and the values. Rice coded values are the gaps from the value
// before (the first from 0), each as its quotient in one bits and a zero bit,
// then its low k bits, packed most significant bit first, the last byte
// padded with zero bits. A bitmap is 8,192 bytes, in which value v is bit
// 7 - v%8 of byte v/8. It returns ErrRPAFilterValues for values that are not
// sorted and distinct.
func EncodeRPAFilter(values []uint16) ([]byte, error) {
	for i := 1; i < len(values); i++ {
		if values[i] <= values[i-1] {
			return nil, ErrRPAFilterValues
		}
	}
	return encodeRPAFilter(values), nil
}

// encodeRPAFilter encodes values that are sorted and distinct.
func encodeRPAFilter(values []uint16) []byte {
	var count bytes.Buffer
	_ = wire.WriteVarInt(&count, 0, uint64(len(values)))
	if len(values) == 0 {
		return count.Bytes()
	}
	k := RPAFilterK(len(values))
	out := append(count.Bytes(), k)
	if k == RPAFilterBitmap {
		bitmap := make([]byte, rpaFilterBitmapBytes)
		for _, v := range values {
			bitmap[v/8] |= 0x80 >> (v % 8)
		}
		return append(out, bitmap...)
	}
	w := rpaBitWriter{out: out}
	var prev uint32
	for _, v := range values {
		d := uint32(v) - prev
		prev = uint32(v)
		for q := d >> k; q > 0; q-- {
			w.bit(true)
		}
		w.bit(false)
		for i := int(k) - 1; i >= 0; i-- {
			w.bit(d>>uint(i)&1 == 1)
		}
	}
	return w.flush()
}

// BuildRPAFilter returns a block's input prefix filter, encoded.
func BuildRPAFilter(block *wire.MsgBlock) []byte {
	// RPABlockValues gives the values sorted and distinct.
	return encodeRPAFilter(RPABlockValues(block))
}

// rpaBitReader reads bits most significant first.
type rpaBitReader struct {
	b   []byte
	pos uint64
}

func (r *rpaBitReader) bit() (bool, bool) {
	if r.pos >= uint64(len(r.b))*8 {
		return false, false
	}
	one := r.b[r.pos/8]&(0x80>>(r.pos%8)) != 0
	r.pos++
	return one, true
}

// DecodeRPAFilter decodes an input prefix filter into its values, in order.
// It refuses a count not in its shortest form or above 65,536, a coding byte
// other than the one the count gives, a value repeated or above 65,535, fewer
// values than the count, a bitmap that holds another number of values, a
// set padding bit and trailing bytes, so that the bytes it takes are the one
// encoding of their values, the one EncodeRPAFilter gives.
func DecodeRPAFilter(b []byte) ([]uint16, error) {
	r := bytes.NewReader(b)
	n, err := wire.ReadVarInt(r, 0)
	if err != nil {
		// ReadVarInt also refuses a count not in its shortest form, with a
		// message error rather than an end of input.
		var msgErr *wire.MessageError
		if errors.As(err, &msgErr) {
			return nil, ErrRPAFilterCount
		}
		return nil, ErrRPAFilterTruncated
	}
	if n > RPAFilterMaxValues {
		return nil, ErrRPAFilterCount
	}
	rest := b[len(b)-r.Len():]
	if n == 0 {
		if len(rest) != 0 {
			return nil, ErrRPAFilterTrailing
		}
		return []uint16{}, nil
	}
	if len(rest) == 0 {
		return nil, ErrRPAFilterTruncated
	}
	k := rest[0]
	if k != RPAFilterK(int(n)) {
		return nil, ErrRPAFilterK
	}
	if k == RPAFilterBitmap {
		return decodeRPABitmap(rest[1:], int(n))
	}
	br := rpaBitReader{b: rest[1:]}
	values := make([]uint16, 0, n)
	var prev uint32
	for i := uint64(0); i < n; i++ {
		var q uint32
		for {
			one, ok := br.bit()
			if !ok {
				return nil, ErrRPAFilterTruncated
			}
			if !one {
				break
			}
			q++
			if q<<k > 0xffff {
				return nil, ErrRPAFilterValue
			}
		}
		d := q << k
		for j := int(k) - 1; j >= 0; j-- {
			one, ok := br.bit()
			if !ok {
				return nil, ErrRPAFilterTruncated
			}
			if one {
				d |= 1 << uint(j)
			}
		}
		if i > 0 && d == 0 {
			return nil, ErrRPAFilterGap
		}
		v := prev + d
		if v > 0xffff {
			return nil, ErrRPAFilterValue
		}
		values = append(values, uint16(v))
		prev = v
	}
	// The bits left in the last byte read must be zero, and no byte may
	// follow it.
	used := (br.pos + 7) / 8
	if used < uint64(len(br.b)) {
		return nil, ErrRPAFilterTrailing
	}
	for br.pos < used*8 {
		if one, _ := br.bit(); one {
			return nil, ErrRPAFilterPadding
		}
	}
	return values, nil
}

// decodeRPABitmap decodes the bitmap of a filter of n values.
func decodeRPABitmap(bitmap []byte, n int) ([]uint16, error) {
	switch {
	case len(bitmap) < rpaFilterBitmapBytes:
		return nil, ErrRPAFilterTruncated
	case len(bitmap) > rpaFilterBitmapBytes:
		return nil, ErrRPAFilterTrailing
	}
	count := 0
	for _, b := range bitmap {
		count += bits.OnesCount8(b)
	}
	if count != n {
		return nil, ErrRPAFilterBitmapCount
	}
	values := make([]uint16, 0, n)
	for i, b := range bitmap {
		for b != 0 {
			j := bits.LeadingZeros8(b)
			values = append(values, uint16(i*8+j))
			b &^= 0x80 >> j
		}
	}
	return values, nil
}

// RPAFilterMatch reports whether sorted values hold one whose first bits
// equal a prefix of 1 to 16 bits: a value in [prefix << (16 - bits),
// (prefix + 1) << (16 - bits)).
func RPAFilterMatch(values []uint16, prefix uint16, prefixBits uint8) bool {
	if prefixBits == 0 || prefixBits > 16 {
		return false
	}
	shift := 16 - uint(prefixBits)
	lo := uint32(prefix) << shift
	hi := (uint32(prefix) + 1) << shift
	i, _ := slices.BinarySearch(values, uint16(min(lo, 0xffff)))
	return lo <= 0xffff && i < len(values) && uint32(values[i]) < hi
}

// GetRPAFilterHash returns the double SHA-256 of an input prefix filter's
// bytes, the hash a cfheaders message lists for it.
func GetRPAFilterHash(filter []byte) chainhash.Hash {
	return chainhash.DoubleHashH(filter)
}

// MakeHeaderForRPAFilter returns an input prefix filter's header: the double
// SHA-256 of its hash and the previous block's filter header, as for the
// other filter types.
func MakeHeaderForRPAFilter(filter []byte, prevHeader chainhash.Hash) chainhash.Hash {
	filterHash := GetRPAFilterHash(filter)
	var b [2 * chainhash.HashSize]byte
	copy(b[:], filterHash[:])
	copy(b[chainhash.HashSize:], prevHeader[:])
	return chainhash.DoubleHashH(b[:])
}
