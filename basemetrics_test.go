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
		trg   ImpactMetric
		valid bool
		score float64
		str   string
		short string
	}

	var cases = []testcase{
		{ImpactMetric_Complete, true, 0.660, "Complete", "C"},
		{ImpactMetric_Partial, true, 0.275, "Partial", "P"},
		{ImpactMetric_None, true, 0.0, "None", "N"},
		{ImpactMetric("test"), false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.Score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestBaseMetricsBaseScore(t *testing.T) {
	type testcase struct {
		trg   BaseMetrics
		score float64
	}

	var cases = []testcase{
		{BaseMetrics{
			Av: AccessVector_Network,
			Ac: AccessComplexity_Midium,
			Au: Authentication_None,
			C:  ImpactMetric_None,
			I:  ImpactMetric_Partial,
			A:  ImpactMetric_None,
		}, 4.3},
		{BaseMetrics{
			Av: AccessVector_Network,
			Ac: AccessComplexity_Low,
			Au: Authentication_None,
			C:  ImpactMetric_Partial,
			I:  ImpactMetric_Partial,
			A:  ImpactMetric_Partial,
		}, 7.5},
		{BaseMetrics{
			Av: AccessVector_Network,
			Ac: AccessComplexity_Midium,
			Au: Authentication_Single,
			C:  ImpactMetric_None,
			I:  ImpactMetric_Partial,
			A:  ImpactMetric_None,
		}, 3.5},
		{BaseMetrics{
			Av: AccessVector_Local,
			Ac: AccessComplexity_Midium,
			Au: Authentication_None,
			C:  ImpactMetric_None,
			I:  ImpactMetric_Complete,
			A:  ImpactMetric_Complete,
		}, 6.3},
		{BaseMetrics{
			Av: AccessVector_Local,
			Ac: AccessComplexity_Midium,
			Au: Authentication_None,
			C:  ImpactMetric_None,
			I:  ImpactMetric_Complete,
			A:  ImpactMetric_Complete,
		}, 6.3},
		{BaseMetrics{
			Av: AccessVector("invalid"),
			Ac: AccessComplexity_Midium,
			Au: Authentication_None,
			C:  ImpactMetric_None,
			I:  ImpactMetric_Complete,
			A:  ImpactMetric_Complete,
		}, math.NaN()},
	}

	for i, c := range cases {
		assert.Equal(t, c.score, c.trg.BaseScore(), "fail on %d", i)
	}
}
