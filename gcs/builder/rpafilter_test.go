// Copyright (c) 2026 The gcash developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil/gcs/builder"
)

// The vectors below were made with a reference written from the filter's
// specification alone (BitcoinCash1/knuth-bch-startos,
// scripts/rpa_filter_vectors.py), which knuth checks its implementation
// against too, and made again with it after the coding rule's amendment of
// 2026-11-26. Each block's header chains from the one before, the first from
// 32 zero bytes.
var rpaFilterBlocks = []struct {
	name        string
	block       string
	values      []uint16
	inputValues [][]uint16
	k           uint8
	filter      string
	filterHash  string
	header      string
}{
	{
		name: "empty",
		block: "0000002000000000000000000000000000000000000000000000000000000000000000009d6475cc74d5e2c36a9c5fa5" +
			"64b25676a0442a86eff51081bd077a9fc0919d2b00f15365ffff7f200000000001010000000100000000000000000000" +
			"00000000000000000000000000000000000000000000ffffffff06010003727061ffffffff0100f2052a010000000151" +
			"00000000",
		values:      []uint16{},
		inputValues: [][]uint16{},
		k:           0,
		filter:      "00",
		filterHash:  "1406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539a",
		header:      "a80ba8d54948ed417954508791bcf9321bcda26c160b77ab695258281c0d3e75",
	},
	{
		name: "one input",
		block: "00000020679d3aae7bad61757b5e1e3e225764d3a90a72d6f383e104953f82f36c7d5235382edb97970c0e4c882a3736" +
			"d227780325ae84c0fdf065b1402c61a949e6ced658f35365ffff7f200000000002010000000100000000000000000000" +
			"00000000000000000000000000000000000000000000ffffffff06010103727061ffffffff0100f2052a010000000151" +
			"0000000002000000011111111111111111111111111111111111111111111111111111111111111111000000000151ff" +
			"ffffff01e803000000000000015100000000",
		values:      []uint16{0x9408},
		inputValues: [][]uint16{{0x9408}},
		k:           15,
		filter:      "010f8a0400",
		filterHash:  "e1452af78ceb4f079714cb094c3f5c69bbb1a0d38bb90fd4fc63365649474fce",
		header:      "1c0123a83da1787bd17ee2b07312e3a2769ab6d6fd2963b97fcd28e595b75c6f",
	},
	{
		name: "two inputs sharing a prefix",
		block: "000000208c3745485793913b4370e90cfc2edba60842edfc107f116fa447338bf101f23ab67e94cdd0d6a920578271a0" +
			"c13997f863e77ae4346962950e36c392dfdc1f56b0f55365ffff7f200000000002010000000100000000000000000000" +
			"00000000000000000000000000000000000000000000ffffffff06010203727061ffffffff0100f2052a010000000151" +
			"0000000002000000022222222222222222222222222222222222222222222222222222222222222222000000000151ff" +
			"ffffff222222222222222222222222222222222222222222222222222222222222222201000000015186ed000001e803" +
			"000000000000015100000000",
		values:      []uint16{0xc3ed},
		inputValues: [][]uint16{{0xc3ed, 0xc3ed}},
		k:           15,
		filter:      "010fa1f680",
		filterHash:  "f423f13e1b97819945f324ed136d136f15a71656b4ae0fd031ff6e287257879c",
		header:      "8f18899a3f80fdbf3ca6f15203b5c016fb0577cf5853ee912d4c88e6685192ca",
	},
	{
		name: "several transactions",
		block: "00000020747869088322e048c5f4dd87ec0a1b1eef99b91b78d8c06b2291e41bad869a2c48e727a0229de260837dba40" +
			"8a3a308097fce37f6b7950954f250f60aa61d74708f85365ffff7f200000000003010000000100000000000000000000" +
			"00000000000000000000000000000000000000000000ffffffff06010303727061ffffffff0100f2052a010000000151" +
			"00000000020000000233333333333333333333333333333333333333333333333333333333333333330000000000ffff" +
			"ffff33333333333333333333333333333333333333333333333333333333333333330100000000ffffffff01e8030000" +
			"000000000151000000000200000003444444444444444444444444444444444444444444444444444444444444444400" +
			"00000015140000000000000000000000000000000000000000feffffff44444444444444444444444444444444444444" +
			"444444444444444444444444440100000015140101010101010101010101010101010101010101fdffffff4444444444" +
			"444444444444444444444444444444444444444444444444444444020000001514020202020202020202020202020202" +
			"0202020202fcffffff01e803000000000000015100000000",
		values:      []uint16{0x0c06, 0x231f, 0x5e33, 0xa8e6, 0xc535},
		inputValues: [][]uint16{{0xc535, 0xa8e6}, {0x5e33, 0x0c06, 0x231f}},
		k:           13,
		filter:      "050d3019719b6299566e2780",
		filterHash:  "eea30a94c8acfa84935aa0a4a2a442a3e709ae60b21ed77e108831a5a9d1565d",
		header:      "6e50997c60f71d3ceb2905e2ed7cec28d294c0c51b645e5508356b42f67b3a3b",
	},
	{
		name: "31 inputs",
		block: "00000020ceac327bc87e749b35938b61e9e0d5b82c37ceaf1c22545e16ad35ee047a5026fa0e9a584e95dcc70d048c79" +
			"8bc45f3c4f25c88bb3b03db97deafda47640d88d60fa5365ffff7f200000000002010000000100000000000000000000" +
			"00000000000000000000000000000000000000000000ffffffff06010403727061ffffffff0100f2052a010000000151" +
			"00000000020000001f55555555555555555555555555555555555555555555555555555555555555550000000000ffff" +
			"ffff55555555555555555555555555555555555555555555555555555555555555550100000000ffffffff5555555555" +
			"5555555555555555555555555555555555555555555555555555550200000000ffffffff555555555555555555555555" +
			"55555555555555555555555555555555555555550300000000ffffffff55555555555555555555555555555555555555" +
			"555555555555555555555555550400000000ffffffff5555555555555555555555555555555555555555555555555555" +
			"5555555555550500000000ffffffff555555555555555555555555555555555555555555555555555555555555555506" +
			"00000000ffffffff55555555555555555555555555555555555555555555555555555555555555550700000000ffffff" +
			"ff55555555555555555555555555555555555555555555555555555555555555550800000000ffffffff555555555555" +
			"55555555555555555555555555555555555555555555555555550900000000ffffffff55555555555555555555555555" +
			"555555555555555555555555555555555555550a00000000ffffffff5555555555555555555555555555555555555555" +
			"5555555555555555555555550b00000000ffffffff555555555555555555555555555555555555555555555555555555" +
			"55555555550c00000000ffffffff55555555555555555555555555555555555555555555555555555555555555550d00" +
			"000000ffffffff55555555555555555555555555555555555555555555555555555555555555550e00000000ffffffff" +
			"55555555555555555555555555555555555555555555555555555555555555550f00000000ffffffff55555555555555" +
			"555555555555555555555555555555555555555555555555551000000000ffffffff5555555555555555555555555555" +
			"5555555555555555555555555555555555551100000000ffffffff555555555555555555555555555555555555555555" +
			"55555555555555555555551200000000ffffffff55555555555555555555555555555555555555555555555555555555" +
			"555555551300000000ffffffff5555555555555555555555555555555555555555555555555555555555555555140000" +
			"0000ffffffff55555555555555555555555555555555555555555555555555555555555555551500000000ffffffff55" +
			"555555555555555555555555555555555555555555555555555555555555551600000000ffffffff5555555555555555" +
			"5555555555555555555555555555555555555555555555551700000000ffffffff555555555555555555555555555555" +
			"55555555555555555555555555555555551800000000ffffffff55555555555555555555555555555555555555555555" +
			"555555555555555555551900000000ffffffff5555555555555555555555555555555555555555555555555555555555" +
			"5555551a00000000ffffffff55555555555555555555555555555555555555555555555555555555555555551b000000" +
			"00ffffffff55555555555555555555555555555555555555555555555555555555555555551c00000000ffffffff5555" +
			"5555555555555555555555555555555555555555555555555555555555551d00000000ffffffff555555555555555555" +
			"55555555555555555555555555555555555555555555551e00000000ffffffff01e803000000000000015100000000",
		values:      []uint16{0x02ed, 0x1013, 0x171b, 0x1874, 0x1d3c, 0x3542, 0x4d39, 0x51de, 0x54bf, 0x5c3e, 0x6ce7, 0x7e8e, 0x81ef, 0x8ffe, 0x9376, 0x96aa, 0x9798, 0x9885, 0xaf16, 0xb033, 0xb08d, 0xb75a, 0xc3ac, 0xd207, 0xd2fd, 0xde98, 0xe39d, 0xebfa, 0xed4c, 0xfc15},
		inputValues: [][]uint16{{0xd2fd, 0x51de, 0xebfa, 0x9376, 0x54bf, 0x96aa, 0xaf16, 0x4d39, 0xb033, 0x8ffe, 0x9885, 0x81ef, 0x1d3c, 0xb75a, 0x171b, 0xb08d, 0x1013, 0x1874, 0xe39d, 0xfc15, 0xed4c, 0x3542, 0x7e8e, 0x02ed, 0x6ce7, 0xc3ac, 0xde98, 0x5c3e, 0x9798, 0xd207, 0xa938}},
		k:           10,
		filter: "1e0a5dbc935841598c8fc037dfbc52ae1b7ff153e69db0f41ede19a0ee1dbf5224742d566f0a5d2d8f6dcdc82e174a97" +
			"5920",
		filterHash: "5773e5c29f136644b9f88d2d3df1cd527d9ed5a68a6773d25b113dc50930f8c0",
		header:     "4b595d03261b964c360e1d9f39a670ada0dd94c5a6298ef947334b7026792489",
	},
}

func rpaHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRPAFilterBlocks builds each vector block's filter from the block, and
// checks its values, the values of each transaction's inputs, the Rice
// parameter, the bytes, their hash and the header chain, and that the bytes
// decode back to the values.
func TestRPAFilterBlocks(t *testing.T) {
	var prev chainhash.Hash
	for _, test := range rpaFilterBlocks {
		var block wire.MsgBlock
		if err := block.Deserialize(bytes.NewReader(rpaHex(t, test.block))); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		values := builder.RPABlockValues(&block)
		if !slices.Equal(values, test.values) {
			t.Errorf("%s: values %04x, want %04x", test.name, values, test.values)
		}
		for i, want := range test.inputValues {
			tx := block.Transactions[i+1]
			if len(tx.TxIn) != len(want) {
				t.Fatalf("%s: transaction %d has %d inputs, want %d", test.name, i+1, len(tx.TxIn), len(want))
			}
			for j, txIn := range tx.TxIn {
				if v := builder.RPAInputValue(txIn); v != want[j] {
					t.Errorf("%s: transaction %d input %d: value %04x, want %04x", test.name, i+1, j, v, want[j])
				}
			}
		}
		if len(test.values) > 0 {
			if k := builder.RPAFilterK(len(test.values)); k != test.k {
				t.Errorf("%s: k %d, want %d", test.name, k, test.k)
			}
		}

		filter := builder.BuildRPAFilter(&block)
		if hex.EncodeToString(filter) != test.filter {
			t.Errorf("%s: filter %x, want %s", test.name, filter, test.filter)
		}
		hash := builder.GetRPAFilterHash(filter)
		if hex.EncodeToString(hash[:]) != test.filterHash {
			t.Errorf("%s: filter hash %x, want %s", test.name, hash[:], test.filterHash)
		}
		header := builder.MakeHeaderForRPAFilter(filter, prev)
		if hex.EncodeToString(header[:]) != test.header {
			t.Errorf("%s: header %x, want %s", test.name, header[:], test.header)
		}
		prev = header

		decoded, err := builder.DecodeRPAFilter(filter)
		if err != nil || !slices.Equal(decoded, test.values) {
			t.Errorf("%s: decoded %04x, %v", test.name, decoded, err)
		}
	}

	// Only the first 30 inputs of a transaction count: the 31st input's
	// value is not among the first 30's, and is not in the filter.
	last := rpaFilterBlocks[len(rpaFilterBlocks)-1]
	inputs := last.inputValues[0]
	if len(inputs) != 31 || slices.Contains(inputs[:30], inputs[30]) ||
		slices.Contains(last.values, inputs[30]) {
		t.Errorf("the 31st input's value %04x is in the filter", inputs[30])
	}
}

// encodeRPA encodes values that the test knows are sorted and distinct.
func encodeRPA(t *testing.T, values []uint16) []byte {
	t.Helper()
	b, err := builder.EncodeRPAFilter(values)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// firstValues returns the values 0 to n-1.
func firstValues(n int) []uint16 {
	values := make([]uint16, n)
	for i := range values {
		values[i] = uint16(i)
	}
	return values
}

// riceBytes Rice codes gaps with parameter k as the reference does, whatever
// k the count would give, so that encodings the decoder must refuse can be
// made.
func riceBytes(k uint, gaps []uint32) []byte {
	var out []byte
	var cur byte
	var used uint
	bit := func(one bool) {
		if one {
			cur |= 0x80 >> used
		}
		used++
		if used == 8 {
			out = append(out, cur)
			cur, used = 0, 0
		}
	}
	for _, d := range gaps {
		for q := d >> k; q > 0; q-- {
			bit(true)
		}
		bit(false)
		for i := int(k) - 1; i >= 0; i-- {
			bit(d>>uint(i)&1 == 1)
		}
	}
	if used > 0 {
		out = append(out, cur)
	}
	return out
}

// TestRPAFilterLarge builds the filter of 1,000 transactions of 30 inputs
// each: transaction j spends outpoints whose txid is j as four little-endian
// bytes and 28 zero bytes, indexes 0 to 29, with empty scripts and sequence
// 0xffffffff. There are enough values for the bitmap.
func TestRPAFilterLarge(t *testing.T) {
	txs := make([]*wire.MsgTx, 0, 1000)
	for j := uint32(1); j <= 1000; j++ {
		var txid chainhash.Hash
		binary.LittleEndian.PutUint32(txid[:4], j)
		tx := wire.NewMsgTx(2)
		for i := uint32(0); i < 30; i++ {
			tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&txid, i), nil))
		}
		txs = append(txs, tx)
	}
	values := builder.RPAValues(txs)
	if len(values) != 24051 || builder.RPAFilterK(len(values)) != builder.RPAFilterBitmap {
		t.Fatalf("%d values, k %d, want 24051 and the bitmap", len(values), builder.RPAFilterK(len(values)))
	}
	if !slices.Equal(values[:4], []uint16{0x0001, 0x0002, 0x000e, 0x000f}) ||
		!slices.Equal(values[len(values)-4:], []uint16{0xfff9, 0xfffa, 0xfffc, 0xfffd}) {
		t.Errorf("first values %04x, last %04x", values[:4], values[len(values)-4:])
	}
	filter := encodeRPA(t, values)
	hash := builder.GetRPAFilterHash(filter)
	if len(filter) != 8196 || hex.EncodeToString(filter[:16]) != "fdf35d106003cf5803bc3d88c206f1b0" ||
		hex.EncodeToString(filter[len(filter)-8:]) != "012cdca4351184ec" ||
		hex.EncodeToString(hash[:]) != "a067316c9de0820f3a0d59e8f8f3afd1faa9fdabe19fcbd0240fc586bd0c0a5c" {

		t.Errorf("filter of %d bytes, %x..%x, hash %x", len(filter), filter[:16], filter[len(filter)-8:], hash[:])
	}
	decoded, err := builder.DecodeRPAFilter(filter)
	if err != nil || !slices.Equal(decoded, values) {
		t.Errorf("decoded %d values, %v", len(decoded), err)
	}
}

// TestRPAFilterAccepted decodes encodings the decoder takes: single values
// at both ends, two values, the most values Rice codes and the fewest a bitmap
// holds, every even value and every value, each the one encoding of its
// values.
func TestRPAFilterAccepted(t *testing.T) {
	even := make([]uint16, 0, 32768)
	for v := 0; v < 65536; v += 2 {
		even = append(even, uint16(v))
	}
	tests := []struct {
		name   string
		values []uint16
		data   []byte
		size   int
		hash   string
	}{
		{"value 0", []uint16{0}, rpaHex(t, "010f0000"), 4,
			"d765bddba686b5d7a4eee92e6da5c4cf23f3fb5d272b71b478d5e7b29beef01b"},
		{"value 65535", []uint16{65535}, rpaHex(t, "010fbfff80"), 5,
			"f604888baa2af992bba2f2511bc214e31c272608c23092cb8bc63e0d0630122b"},
		{"two values", []uint16{1, 2}, rpaHex(t, "020e00020004"), 6,
			"fc45657f3a482e5872d033a5c86387e5801c723c4c11caed079b92810a61b447"},
		{"first 19196 values, k = 1", firstValues(19196), encodeRPA(t, firstValues(19196)), 4803,
			"c87c720767d86452f2dfde01c6a5300a755a1fc9eabda48f4d4b56dc4ad17fea"},
		{"first 19197 values, bitmap", firstValues(19197), encodeRPA(t, firstValues(19197)), 8196,
			"355b13f4d81ff87e20fc33ce4ef7931acdbb3867f7b128bb71286322d3850001"},
		{"even values, bitmap", even, encodeRPA(t, even), 8196,
			"b0abac56021c4436c49a9de58243b2d5594633503c83cddd2e190da6a5be37b7"},
		{"every value", firstValues(65536), encodeRPA(t, firstValues(65536)), 8198,
			"79d65549e1801072cda4736a9b36ee687cdb2ff6b94139437f242ddfc1251c01"},
	}
	for _, test := range tests {
		got, err := builder.DecodeRPAFilter(test.data)
		if err != nil || !slices.Equal(got, test.values) {
			t.Errorf("%s: decoded %d values, %v", test.name, len(got), err)
			continue
		}
		if b := encodeRPA(t, got); !bytes.Equal(b, test.data) {
			t.Errorf("%s: the values encode to other bytes", test.name)
		}
		hash := builder.GetRPAFilterHash(test.data)
		if len(test.data) != test.size || hex.EncodeToString(hash[:]) != test.hash {
			t.Errorf("%s: %d bytes, hash %x; want %d and %s", test.name, len(test.data), hash[:], test.size, test.hash)
		}
	}
}

// TestRPAFilterRefused checks that the decoder refuses each malformed
// encoding, for the reason the vectors give.
func TestRPAFilterRefused(t *testing.T) {
	tests := []struct {
		name string
		data string
		err  error
	}{
		{"empty", "", builder.ErrRPAFilterTruncated},
		{"count only", "01", builder.ErrRPAFilterTruncated},
		{"no stream", "010f", builder.ErrRPAFilterTruncated},
		{"k above 16", "0111000000", builder.ErrRPAFilterK},
		{"bitmap byte for one value", "0110000000", builder.ErrRPAFilterK},
		// The value 3 with k = 0, where one value gives k = 15: an
		// encoding of the values other than the one, which the
		// specification refuses since its amendment of 2026-11-16.
		{"k below the one N gives", "0100e0", builder.ErrRPAFilterK},
		{"k one below the one N gives", "010e0006", builder.ErrRPAFilterK},
		{"gap of 0", "020e000a0000", builder.ErrRPAFilterGap},
		{"value above 65535", "010fc00000", builder.ErrRPAFilterValue},
		{"sum above 65535", "020eefffc00080", builder.ErrRPAFilterValue},
		{"fewer values", "020e000a", builder.ErrRPAFilterTruncated},
		// One value and then the bytes of another: whether they are read
		// as a second value or as bytes after the last, they are refused.
		{"more values", "010f00070009", builder.ErrRPAFilterTrailing},
		{"padding", "020e00000005", builder.ErrRPAFilterPadding},
		{"trailing after none", "0000", builder.ErrRPAFilterTrailing},
		{"trailing after one", "010f000700", builder.ErrRPAFilterTrailing},
		{"long count", "fd01000f0007", builder.ErrRPAFilterCount},
		{"count above 65536", "fe010001000000", builder.ErrRPAFilterCount},
	}
	for _, test := range tests {
		if _, err := builder.DecodeRPAFilter(rpaHex(t, test.data)); !errors.Is(err, test.err) {
			t.Errorf("%s: got %v, want %v", test.name, err, test.err)
		}
	}

	// Around the bitmap, built as the reference builds them and checked
	// against its hashes: Rice coding where the count gives the bitmap, a
	// bitmap where it gives Rice coding, a bitmap with a value more than
	// its count, and bitmaps a byte short and a byte long.
	gaps := make([]uint32, 19197)
	for i := 1; i < len(gaps); i++ {
		gaps[i] = 1
	}
	rice19197 := append([]byte{0xfd, 0xfd, 0x4a, 1}, riceBytes(1, gaps)...)
	bitmap19196 := append([]byte{0xfd, 0xfc, 0x4a}, encodeRPA(t, append(firstValues(19196), 65535))[3:]...)
	bitmap19197 := encodeRPA(t, firstValues(19197))
	oneMore := slices.Clone(bitmap19197)
	oneMore[len(oneMore)-1] |= 1
	big := []struct {
		name string
		data []byte
		hash string
		err  error
	}{
		{"rice for 19197 values", rice19197,
			"c551e5e24157e4367c8cc57f079c261da9c23a8eb8b70f018a99841b126e453d", builder.ErrRPAFilterK},
		{"bitmap for 19196 values", bitmap19196,
			"9b1c0366745c1b16661d5e317f16ee6d75a1d9ff3699985247e520b8c2ff9c52", builder.ErrRPAFilterK},
		{"bitmap with a value too many", oneMore,
			"2586850d51f1817c222f702d38b16670fbe12717088b75bc13fc9fff19176e5b", builder.ErrRPAFilterBitmapCount},
		{"bitmap a byte short", bitmap19197[:len(bitmap19197)-1],
			"a1a425d9b033a1f3f6e77f3364e07feb1976ca08d6d3c2ae8147c9a27cc084c6", builder.ErrRPAFilterTruncated},
		{"bitmap a byte long", append(slices.Clone(bitmap19197), 0),
			"f4ebf525e4ef4851cee0e4aef8e29461070b672df51702b2f225d44224bafb3b", builder.ErrRPAFilterTrailing},
	}
	for _, test := range big {
		if hash := builder.GetRPAFilterHash(test.data); hex.EncodeToString(hash[:]) != test.hash {
			t.Errorf("%s: built bytes with hash %x, want %s", test.name, hash[:], test.hash)
		}
		if _, err := builder.DecodeRPAFilter(test.data); !errors.Is(err, test.err) {
			t.Errorf("%s: got %v, want %v", test.name, err, test.err)
		}
	}
}

// TestEncodeRPAFilterValues checks that the encoder refuses values that are
// not sorted or not distinct, and encodes no values as a count of 0.
func TestEncodeRPAFilterValues(t *testing.T) {
	for _, values := range [][]uint16{{2, 1}, {1, 1}, {0, 5, 5, 9}, {65535, 0}} {
		if _, err := builder.EncodeRPAFilter(values); !errors.Is(err, builder.ErrRPAFilterValues) {
			t.Errorf("values %04x: got %v", values, err)
		}
	}
	if b, err := builder.EncodeRPAFilter(nil); err != nil || !bytes.Equal(b, []byte{0}) {
		t.Errorf("no values: %x, %v", b, err)
	}
}

// TestRPAFilterK checks the coding byte at the counts where it changes, at
// both ends, and for counts that have none.
func TestRPAFilterK(t *testing.T) {
	tests := []struct {
		n int
		k uint8
	}{
		{1, 15}, {2, 14}, {3, 13}, {6, 13}, {7, 12}, {14, 12}, {15, 11}, {29, 11},
		{30, 10}, {60, 10}, {61, 9}, {122, 9}, {123, 8}, {245, 8}, {246, 7},
		{493, 7}, {494, 6}, {991, 6}, {992, 5}, {1996, 5}, {1997, 4}, {4050, 4},
		{4051, 3}, {8355, 3}, {8356, 2}, {18054, 2}, {18055, 1}, {19196, 1},
		{19197, builder.RPAFilterBitmap}, {65536, builder.RPAFilterBitmap},
		{0, 0}, {-1, 0}, {65537, 0},
	}
	for _, test := range tests {
		if k := builder.RPAFilterK(test.n); k != test.k {
			t.Errorf("%d values: k %d, want %d", test.n, k, test.k)
		}
	}
}

// expectedRiceBits returns, for n distinct values drawn at random, the
// expected number of bits of their Rice coded gaps at each k from 0 to 15.
// The gaps around n random values of 65,536 are a random split of the
// 65,536 - n values left out into n + 1 parts, so each part g has
// P(g >= m) = C(65536 - m, n) / C(65536, n). The first coded gap is g and
// each later one is g + 1, and E[floor(x / 2^k)] = sum over t >= 1 of
// P(x >= t 2^k).
func expectedRiceBits(n int) [16]float64 {
	const m = builder.RPAFilterMaxValues
	var first, later [16]float64
	p := 1.0 // P(g >= i)
	for i := 0; i <= m-n; i++ {
		if i > 0 {
			p *= float64(m-n-i+1) / float64(m-i+1)
			for k := 0; k < 16 && i%(1<<k) == 0; k++ {
				first[k] += p
			}
		}
		for k := 0; k < 16 && (i+1)%(1<<k) == 0; k++ {
			later[k] += p
		}
	}
	var out [16]float64
	for k := range out {
		out[k] = float64(n*(1+k)) + first[k] + float64(n-1)*later[k]
	}
	return out
}

// TestRPAFilterKSmallest checks, on both sides of every count where the
// coding byte changes, that the byte RPAFilterK gives is the coding with the
// fewest expected bits for values drawn at random: the Rice parameter whose
// expectation is the smallest, the larger one on a tie, or the bitmap's
// 65,536 bits once every parameter takes more.
func TestRPAFilterKSmallest(t *testing.T) {
	counts := []int{1, 2, 3, 6, 7, 14, 15, 29, 30, 60, 61, 122, 123, 245, 246, 493, 494,
		991, 992, 1996, 1997, 4050, 4051, 8355, 8356, 18054, 18055, 19196, 19197, 30000}
	for _, n := range counts {
		bits := expectedRiceBits(n)
		best := 0
		for k := 1; k < 16; k++ {
			// Ties to within rounding (one value: k = 14 and 15 both
			// take 16.5 bits) go to the larger k.
			if bits[k] <= bits[best]+1e-9 {
				best = k
			}
		}
		want := uint8(best)
		if bits[best] > builder.RPAFilterMaxValues {
			want = builder.RPAFilterBitmap
		}
		if k := builder.RPAFilterK(n); k != want {
			t.Errorf("%d values: coding %d, but %d is the smallest (%.3f bits at k = %d)", n, k, want, bits[best], best)
		}
	}
}

// TestRPAFilterMainnet checks the value of a real payment to a reusable
// payment address: mainnet transaction
// 73df724caf64c5df016c8cb5a255def1ba09bc41a26bf77e368c913a156bf724, in block
// 893146 (000000000000000000cfc3785c2574200a7dfe4f511ecfb023ad6c8fbfb327ec),
// which pays the paycode Fulcrum's README lists for donations,
// paycode:qygqyce24f7n6q2u36r8t332z5426ul78v7z0ynl6v9wlmk9tt28adksqgc0fzge8fk6ux8cj9tjvp8mkakvfzkgwqzj5h4n9tnfcpscsn7wxqqqqqqqzzmxze04.
// That paycode has a prefix size of 16 bits and the scan key
// 02632aaa7d3d015c8e8675c62a152aad73fe3b3c27927fd30aefeec55ad47eb6d0, so the
// receiver's prefix is 632a, the 16 bits after the key's first byte. Electron
// Cash grinds the first input, here the only one, and the transaction has its
// marks: a Schnorr signature with sighash 0x41, sequence 0xfffffffe and a lock
// time one below its block's height. The output it paid was later spent with
// an uncompressed key, as Electron Cash derives the keys of paycode payments,
// together with the outputs of two more transactions whose first inputs give
// 632a as well.
func TestRPAFilterMainnet(t *testing.T) {
	raw := rpaHex(t, "0100000001bbee41aa77666586111fe562ba679731b2ba493002ab552b31a1dcf2a1e828903e0000006441"+
		"b7a2b648f1d1f0b0d51691f424dffb840f8d5bad1ffe07d1684e20f6843c7ef79fd660827e4d3959472fe4d1198d8f6c"+
		"152799aa3ee652aa477d13b914eaa14e4121028be3c38f3333ccdf44c411ad257c2b75ddae455daf557cb862fb51d22e"+
		"f72f74feffffff02f05b7c00000000001976a914b8f55d367cfd0891083c1af0bee39a2e81361a0788ac809698000000"+
		"00001976a914d2f9ba1f2be88a3b731d78566c6f2e183c0f16c888acd9a00d00")
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if id := tx.TxHash().String(); id != "73df724caf64c5df016c8cb5a255def1ba09bc41a26bf77e368c913a156bf724" {
		t.Fatalf("transaction ID %s", id)
	}
	if v := builder.RPAInputValue(tx.TxIn[0]); v != 0x632a {
		t.Fatalf("the first input's value is %04x, want the receiver's prefix 632a", v)
	}
	values := builder.RPAValues([]*wire.MsgTx{&tx})
	filter := encodeRPA(t, values)
	decoded, err := builder.DecodeRPAFilter(filter)
	if err != nil || !slices.Equal(decoded, []uint16{0x632a}) {
		t.Fatalf("filter %x decodes to %04x, %v", filter, decoded, err)
	}
	for _, p := range []struct {
		prefix uint16
		bits   uint8
	}{{0x632a, 16}, {0x632, 12}, {0x63, 8}, {0x6, 4}} {
		if !builder.RPAFilterMatch(decoded, p.prefix, p.bits) {
			t.Errorf("the filter doesn't match the receiver's prefix %x of %d bits", p.prefix, p.bits)
		}
	}
	if builder.RPAFilterMatch(decoded, 0x632b, 16) {
		t.Error("the filter matches another 16-bit prefix")
	}
}

// TestRPAFilterMatch checks prefixes of 4, 8, 12 and 16 bits against values
// at the edges of their ranges.
func TestRPAFilterMatch(t *testing.T) {
	values := []uint16{0x0000, 0x12ff, 0x1300, 0xa5a5, 0xffff}
	tests := []struct {
		prefix uint16
		bits   uint8
		match  bool
	}{
		{0x0, 4, true}, {0x1, 4, true}, {0x2, 4, false}, {0xa, 4, true}, {0xf, 4, true},
		{0x12, 8, true}, {0x13, 8, true}, {0x14, 8, false}, {0xff, 8, true}, {0xfe, 8, false},
		{0x12f, 12, true}, {0x130, 12, true}, {0x131, 12, false}, {0xa5a, 12, true},
		{0x12ff, 16, true}, {0x1300, 16, true}, {0x1301, 16, false}, {0xffff, 16, true}, {0xfffe, 16, false},
		{0x0000, 16, true}, {0x0001, 16, false},
		// Not a prefix: no bits, more than 16, or bits set past its length.
		{0, 0, false}, {0x12ff, 17, false}, {0x1ff, 8, false},
	}
	for _, test := range tests {
		if got := builder.RPAFilterMatch(values, test.prefix, test.bits); got != test.match {
			t.Errorf("prefix %x/%d: match %v, want %v", test.prefix, test.bits, got, test.match)
		}
	}
	if builder.RPAFilterMatch(nil, 0, 4) {
		t.Error("an empty filter matches")
	}
}
