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
		{AccessComplexity_Medium, true, 0.61, "Medium", "M"},
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

func TestExploitability(t *testing.T) {
	type testcase struct {
		trg   Exploitability
		valid bool
		score float64
		str   string
		short string
	}
	var cases = []testcase{
		{Exploitability_Unproven, true, 0.85, "Unproven", "U"},
		{Exploitability_ProofOfConcept, true, 0.90, "Proof-of-concept", "POC"},
		{Exploitability_Functional, true, 0.95, "Functional", "F"},
		{Exploitability_High, true, 1.00, "High", "H"},
		{Exploitability_NotDefined, false, 1.00, "Not Defined", "ND"},
		{Exploitability(""), false, 1.00, "Not Defined", "ND"},
		{Exploitability("test"), false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.Score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestRemediationLevel(t *testing.T) {
	type testcase struct {
		trg   RemediationLevel
		valid bool
		score float64
		str   string
		short string
	}
	var cases = []testcase{
		{RemediationLevel_OfficialFix, true, 0.87, "Official-fix", "OF"},
		{RemediationLevel_TemporaryFix, true, 0.90, "Temporary-fix", "T"},
		{RemediationLevel_Workaround, true, 0.95, "Workaround", "W"},
		{RemediationLevel_Unavailable, true, 1.00, "Unavailable", "U"},
		{RemediationLevel_NotDefined, false, 1.00, "Not Defined", "ND"},
		{RemediationLevel(""), false, 1.00, "Not Defined", "ND"},
		{RemediationLevel("test"), false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.Score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestReportConfidence(t *testing.T) {
	type testcase struct {
		trg   ReportConfidence
		valid bool
		score float64
		str   string
		short string
	}
	var cases = []testcase{
		{ReportConfidence_Unconfirmed, true, 0.90, "Unconfirmed", "UC"},
		{ReportConfidence_Uncorroborated, true, 0.95, "Uncorroborated", "UR"},
		{ReportConfidence_Confirmed, true, 1.00, "Confirmed", "C"},
		{ReportConfidence_NotDefined, false, 1.00, "Not Defined", "ND"},
		{ReportConfidence(""), false, 1.00, "Not Defined", "ND"},
		{ReportConfidence("test"), false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.Score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestCollateralDamagePotential(t *testing.T) {
	type testcase struct {
		trg   CollateralDamagePotential
		valid bool
		score float64
		str   string
		short string
	}
	var cases = []testcase{
		{CollateralDamagePotential_None, true, 0.00, "None", "N"},
		{CollateralDamagePotential_Low, true, 0.10, "Low", "L"},
		{CollateralDamagePotential_LowMedium, true, 0.30, "Low-Medium", "LM"},
		{CollateralDamagePotential_MediumHigh, true, 0.40, "Medium-High", "MH"},
		{CollateralDamagePotential_High, true, 0.50, "High", "H"},
		{CollateralDamagePotential_NotDefined, false, 0.00, "Not Defined", "ND"},
		{CollateralDamagePotential(""), false, 0.00, "Not Defined", "ND"},
		{CollateralDamagePotential("test"), false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.Score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestTargetDistribution(t *testing.T) {
	type testcase struct {
		trg   TargetDistribution
		valid bool
		score float64
		str   string
		short string
	}
	var cases = []testcase{
		{TargetDistribution_None, true, 0.00, "None", "N"},
		{TargetDistribution_Low, true, 0.25, "Low", "L"},
		{TargetDistribution_Medium, true, 0.75, "Medium", "M"},
		{TargetDistribution_High, true, 1.00, "High", "H"},
		{TargetDistribution_NotDefined, false, 1.00, "Not Defined", "ND"},
		{TargetDistribution(""), false, 1.00, "Not Defined", "ND"},
		{TargetDistribution("test"), false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.Score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestRequirement(t *testing.T) {
	type testcase struct {
		trg   Requirement
		valid bool
		score float64
		str   string
		short string
	}
	var cases = []testcase{
		{Requirement_Low, true, 0.5, "Low", "L"},
		{Requirement_Medium, true, 1.0, "Medium", "M"},
		{Requirement_High, true, 1.51, "High", "H"},
		{Requirement_NotDefined, false, 1.00, "Not Defined", "ND"},
		{Requirement(""), false, 1.00, "Not Defined", "ND"},
		{Requirement("test"), false, math.NaN(), "", ""},
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
			AV: AccessVector_Network,
			AC: AccessComplexity_Medium,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_None,
		}, 4.3},
		{BaseVectors{
			AV: AccessVector_Network,
			AC: AccessComplexity_Low,
			Au: Authentication_None,
			C:  Impact_Partial,
			I:  Impact_Partial,
			A:  Impact_Partial,
		}, 7.5},
		{BaseVectors{
			AV: AccessVector_Network,
			AC: AccessComplexity_Medium,
			Au: Authentication_Single,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_None,
		}, 3.5},
		{BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_Medium,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Complete,
			A:  Impact_Complete,
		}, 6.3},
		{BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_Medium,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Complete,
			A:  Impact_Complete,
		}, 6.3},
		{BaseVectors{
			AV: AccessVector("invalid"),
			AC: AccessComplexity_Medium,
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
