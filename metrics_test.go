package cvss

import (
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
)

func TestAccessVector(t *testing.T) {
	type testcase struct {
		trg     AccessVector
		valid   bool
		defined bool
		score   float64
		str     string
		short   string
	}

	var cases = []testcase{
		{AccessVector_Local, true, true, 0.395, "Local", "L"},
		{AccessVector_AdjacentNetwork, true, true, 0.646, "Adjacent Network", "A"},
		{AccessVector_Network, true, true, 1.0, "Network", "N"},
		{AccessVector("test"), false, false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.isDefined(), c.defined, "fail on %d", i)
		assert.Equal(t, c.trg.score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestAccessComplexity(t *testing.T) {
	type testcase struct {
		trg     AccessComplexity
		valid   bool
		defined bool
		score   float64
		str     string
		short   string
	}

	var cases = []testcase{
		{AccessComplexity_High, true, true, 0.35, "High", "H"},
		{AccessComplexity_Medium, true, true, 0.61, "Medium", "M"},
		{AccessComplexity_Low, true, true, 0.71, "Low", "L"},
		{AccessComplexity("test"), false, false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.isDefined(), c.defined, "fail on %d", i)
		assert.Equal(t, c.trg.score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestAuthentication(t *testing.T) {
	type testcase struct {
		trg     Authentication
		valid   bool
		defined bool
		score   float64
		str     string
		short   string
	}

	var cases = []testcase{
		{Authentication_Multiple, true, true, 0.45, "Multiple", "M"},
		{Authentication_Single, true, true, 0.56, "Single", "S"},
		{Authentication_None, true, true, 0.704, "None", "N"},
		{Authentication("test"), false, false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.isDefined(), c.defined, "fail on %d", i)
		assert.Equal(t, c.trg.score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestConfidentiality(t *testing.T) {
	type testcase struct {
		trg     Impact
		valid   bool
		defined bool
		score   float64
		str     string
		short   string
	}

	var cases = []testcase{
		{Impact_Complete, true, true, 0.660, "Complete", "C"},
		{Impact_Partial, true, true, 0.275, "Partial", "P"},
		{Impact_None, true, true, 0.0, "None", "N"},
		{Impact("test"), false, false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.isDefined(), c.defined, "fail on %d", i)
		assert.Equal(t, c.trg.score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestExploitability(t *testing.T) {
	type testcase struct {
		trg     Exploitability
		valid   bool
		defined bool
		score   float64
		str     string
		short   string
	}
	var cases = []testcase{
		{Exploitability_Unproven, true, true, 0.85, "Unproven", "U"},
		{Exploitability_ProofOfConcept, true, true, 0.90, "Proof-of-concept", "POC"},
		{Exploitability_Functional, true, true, 0.95, "Functional", "F"},
		{Exploitability_High, true, true, 1.00, "High", "H"},
		{Exploitability_NotDefined, true, false, 1.00, "Not Defined", "ND"},
		{Exploitability(""), true, false, 1.00, "Not Defined", "ND"},
		{Exploitability("test"), false, false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.isDefined(), c.defined, "fail on %d", i)
		assert.Equal(t, c.trg.score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestRemediationLevel(t *testing.T) {
	type testcase struct {
		trg     RemediationLevel
		valid   bool
		defined bool
		score   float64
		str     string
		short   string
	}
	var cases = []testcase{
		{RemediationLevel_OfficialFix, true, true, 0.87, "Official-fix", "OF"},
		{RemediationLevel_TemporaryFix, true, true, 0.90, "Temporary-fix", "T"},
		{RemediationLevel_Workaround, true, true, 0.95, "Workaround", "W"},
		{RemediationLevel_Unavailable, true, true, 1.00, "Unavailable", "U"},
		{RemediationLevel_NotDefined, true, false, 1.00, "Not Defined", "ND"},
		{RemediationLevel(""), true, false, 1.00, "Not Defined", "ND"},
		{RemediationLevel("test"), false, false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.isDefined(), c.defined, "fail on %d", i)
		assert.Equal(t, c.trg.score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestReportConfidence(t *testing.T) {
	type testcase struct {
		trg     ReportConfidence
		valid   bool
		defined bool
		score   float64
		str     string
		short   string
	}
	var cases = []testcase{
		{ReportConfidence_Unconfirmed, true, true, 0.90, "Unconfirmed", "UC"},
		{ReportConfidence_Uncorroborated, true, true, 0.95, "Uncorroborated", "UR"},
		{ReportConfidence_Confirmed, true, true, 1.00, "Confirmed", "C"},
		{ReportConfidence_NotDefined, true, false, 1.00, "Not Defined", "ND"},
		{ReportConfidence(""), true, false, 1.00, "Not Defined", "ND"},
		{ReportConfidence("test"), false, false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.isDefined(), c.defined, "fail on %d", i)
		assert.Equal(t, c.trg.score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestCollateralDamagePotential(t *testing.T) {
	type testcase struct {
		trg     CollateralDamagePotential
		valid   bool
		defined bool
		score   float64
		str     string
		short   string
	}
	var cases = []testcase{
		{CollateralDamagePotential_None, true, true, 0.00, "None", "N"},
		{CollateralDamagePotential_Low, true, true, 0.10, "Low", "L"},
		{CollateralDamagePotential_LowMedium, true, true, 0.30, "Low-Medium", "LM"},
		{CollateralDamagePotential_MediumHigh, true, true, 0.40, "Medium-High", "MH"},
		{CollateralDamagePotential_High, true, true, 0.50, "High", "H"},
		{CollateralDamagePotential_NotDefined, true, false, 0.00, "Not Defined", "ND"},
		{CollateralDamagePotential(""), true, false, 0.00, "Not Defined", "ND"},
		{CollateralDamagePotential("test"), false, false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.isDefined(), c.defined, "fail on %d", i)
		assert.Equal(t, c.trg.score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestTargetDistribution(t *testing.T) {
	type testcase struct {
		trg     TargetDistribution
		valid   bool
		defined bool
		score   float64
		str     string
		short   string
	}
	var cases = []testcase{
		{TargetDistribution_None, true, true, 0.00, "None", "N"},
		{TargetDistribution_Low, true, true, 0.25, "Low", "L"},
		{TargetDistribution_Medium, true, true, 0.75, "Medium", "M"},
		{TargetDistribution_High, true, true, 1.00, "High", "H"},
		{TargetDistribution_NotDefined, true, false, 1.00, "Not Defined", "ND"},
		{TargetDistribution(""), true, false, 1.00, "Not Defined", "ND"},
		{TargetDistribution("test"), false, false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.isDefined(), c.defined, "fail on %d", i)
		assert.Equal(t, c.trg.score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}

func TestRequirement(t *testing.T) {
	type testcase struct {
		trg     Requirement
		valid   bool
		defined bool
		score   float64
		str     string
		short   string
	}
	var cases = []testcase{
		{Requirement_Low, true, true, 0.5, "Low", "L"},
		{Requirement_Medium, true, true, 1.0, "Medium", "M"},
		{Requirement_High, true, true, 1.51, "High", "H"},
		{Requirement_NotDefined, true, false, 1.00, "Not Defined", "ND"},
		{Requirement(""), true, false, 1.00, "Not Defined", "ND"},
		{Requirement("test"), false, false, math.NaN(), "", ""},
	}

	for i, c := range cases {
		assert.Equal(t, c.trg.IsValid(), c.valid, "fail on %d", i)
		assert.Equal(t, c.trg.isDefined(), c.defined, "fail on %d", i)
		assert.Equal(t, c.trg.score(), c.score, "fail on %d", i)
		assert.Equal(t, c.trg.String(), c.str, "fail on %d", i)
		assert.Equal(t, c.trg.StringShort(), c.short, "fail on %d", i)
	}
}
