package cvss

import (
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
)

func TestAccessVector(t *testing.T) {
	type testcase struct {
		trg   AccessVector
		valid bool
		score float64
		str   string
		short string
	}

	var cases = []testcase{
		{AccessVector_Local, true, 0.395, "Local", "L"},
		{AccessVector_AdjacentNetwork, true, 0.646, "Adjacent Network", "A"},
		{AccessVector_Network, true, 1.0, "Network", "N"},
		{AccessVector("test"), false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.Score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestAccessComplexity(t *testing.T) {
	type testcase struct {
		trg   AccessComplexity
		valid bool
		score float64
		str   string
		short string
	}

	var cases = []testcase{
		{AccessComplexity_High, true, 0.35, "High", "H"},
		{AccessComplexity_Midium, true, 0.61, "Midium", "M"},
		{AccessComplexity_Low, true, 0.71, "Low", "L"},
		{AccessComplexity("test"), false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.Score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestAuthentication(t *testing.T) {
	type testcase struct {
		trg   Authentication
		valid bool
		score float64
		str   string
		short string
	}

	var cases = []testcase{
		{Authentication_Multiple, true, 0.45, "Multiple", "M"},
		{Authentication_Single, true, 0.56, "Single", "S"},
		{Authentication_None, true, 0.704, "None", "N"},
		{Authentication("test"), false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.Score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestConfidentiality(t *testing.T) {
	type testcase struct {
		trg   Impact
		valid bool
		score float64
		str   string
		short string
	}

	var cases = []testcase{
		{Impact_Complete, true, 0.660, "Complete", "C"},
		{Impact_Partial, true, 0.275, "Partial", "P"},
		{Impact_None, true, 0.0, "None", "N"},
		{Impact("test"), false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.Score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestBaseVectorsBaseScore(t *testing.T) {
	type testcase struct {
		trg   BaseVectors
		score float64
	}

	var cases = []testcase{
		{BaseVectors{
			Av: AccessVector_Network,
			Ac: AccessComplexity_Midium,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_None,
		}, 4.3},
		{BaseVectors{
			Av: AccessVector_Network,
			Ac: AccessComplexity_Low,
			Au: Authentication_None,
			C:  Impact_Partial,
			I:  Impact_Partial,
			A:  Impact_Partial,
		}, 7.5},
		{BaseVectors{
			Av: AccessVector_Network,
			Ac: AccessComplexity_Midium,
			Au: Authentication_Single,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_None,
		}, 3.5},
		{BaseVectors{
			Av: AccessVector_Local,
			Ac: AccessComplexity_Midium,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Complete,
			A:  Impact_Complete,
		}, 6.3},
		{BaseVectors{
			Av: AccessVector_Local,
			Ac: AccessComplexity_Midium,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Complete,
			A:  Impact_Complete,
		}, 6.3},
		{BaseVectors{
			Av: AccessVector("invalid"),
			Ac: AccessComplexity_Midium,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Complete,
			A:  Impact_Complete,
		}, math.NaN()},
	}

	for i, c := range cases {
		assert.Equal(t, c.score, c.trg.BaseScore(), "fail on %d", i)
	}
}

func TestParseBaseVectors(t *testing.T) {
	type testcase struct {
		input   string
		output  BaseVectors
		iserror bool
	}
	cases := []testcase{
		{"(AV:L/AC:H/Au:N/C:N/I:P/A:C)", BaseVectors{
			Av: AccessVector_Local,
			Ac: AccessComplexity_High,
			Au: Authentication_None,
			C: Impact_None,
			I: Impact_Partial,
			A: Impact_Complete,
		}, false},
		{"(AV:L/AC:H/Au:N/C:N/I:P/A:C)", BaseVectors{
			Av: AccessVector_Local,
			Ac: AccessComplexity_High,
			Au: Authentication_None,
			C: Impact_None,
			I: Impact_Partial,
			A: Impact_Complete,
		}, false},
		{"AV:L/AC:H/Au:N/C:N/I:P/A:C", BaseVectors{}, true},
		{"123(AV:L/AC:H/Au:N/C:N/I:P/A:C)", BaseVectors{}, true},
	}

	for i, c := range cases {
		m, err := ParseBaseVectors(c.input)
		if c.iserror {
			assert.Error(t, err, "%d", i)
			continue
		} else {
			assert.Nil(t, err, "%d", i)
			assert.Equal(t, c.output, m, "%d", i)
		}
	}

	return
}
