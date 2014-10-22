package cvss

import (
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
)

func TestParseBaseVectors(t *testing.T) {
	type testcase struct {
		input   string
		output  BaseVectors
		iserror bool
	}
	cases := []testcase{
		{"(AV:L/AC:H/Au:N/C:N/I:P/A:C)", BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_High,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_Complete,
		}, false},
		{"(AV:L/AC:H/Au:N/C:N/I:P/A:C)", BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_High,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_Complete,
		}, false},
		{"(AV:L/AC:H/Au:N/C:N/I:P/A:C/E:POC/RL:OF/RC:C)", BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_High,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_Complete,
			E:  Exploitability_ProofOfConcept,
			RL: RemediationLevel_OfficialFix,
			RC: ReportConfidence_Confirmed,
		}, false},
		{"(AV:L/AC:L/Au:M/C:C/I:N/A:P/E:F/RL:T/RC:UR)", BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_Low,
			Au: Authentication_Multiple,
			C:  Impact_Complete,
			I:  Impact_None,
			A:  Impact_Partial,
			E:  Exploitability_Functional,
			RL: RemediationLevel_TemporaryFix,
			RC: ReportConfidence_Uncorroborated,
		}, false},
		{"(AV:L/AC:H/Au:N/C:N/I:P/A:C/E:POC/RL:OF/RC:C/CDP:L/TD:M/CR:L/IR:L/AR:H)", BaseVectors{
			AV:  AccessVector_Local,
			AC:  AccessComplexity_High,
			Au:  Authentication_None,
			C:   Impact_None,
			I:   Impact_Partial,
			A:   Impact_Complete,
			E:   Exploitability_ProofOfConcept,
			RL:  RemediationLevel_OfficialFix,
			RC:  ReportConfidence_Confirmed,
			CDP: CollateralDamagePotential_Low,
			TD:  TargetDistribution_Medium,
			CR:  Requirement_Low,
			IR:  Requirement_Low,
			AR:  Requirement_High,
		}, false},
		{"(AV:L/AC:L/Au:M/C:C/I:N/A:P/E:F/RL:T/RC:UR/CDP:MH/TD:H/CR:M/IR:L/AR:M)", BaseVectors{
			AV:  AccessVector_Local,
			AC:  AccessComplexity_Low,
			Au:  Authentication_Multiple,
			C:   Impact_Complete,
			I:   Impact_None,
			A:   Impact_Partial,
			E:   Exploitability_Functional,
			RL:  RemediationLevel_TemporaryFix,
			RC:  ReportConfidence_Uncorroborated,
			CDP: CollateralDamagePotential_MediumHigh,
			TD:  TargetDistribution_High,
			CR:  Requirement_Medium,
			IR:  Requirement_Low,
			AR:  Requirement_Medium,
		}, false},
		{"AV:L/AC:H/Au:N/C:N/I:P/A:C", BaseVectors{}, true},
		{"123(AV:L/AC:H/Au:N/C:N/I:P/A:C)", BaseVectors{}, true},
		{"(AV:L/AC:H/Au:N/C:N/I:P/A:C/E:F)", BaseVectors{}, true},
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

func TestBaseVectorsString(t *testing.T) {
	type testcase struct {
		input  BaseVectors
		expect string
	}
	cases := []testcase{
		{BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_High,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_Complete,
		}, "(AV:L/AC:H/Au:N/C:N/I:P/A:C)"},
		{BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_High,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_Complete,
		}, "(AV:L/AC:H/Au:N/C:N/I:P/A:C)"},
		{BaseVectors{
			AV:  AccessVector_Local,
			AC:  AccessComplexity_Low,
			Au:  Authentication_Multiple,
			C:   Impact_Complete,
			I:   Impact_None,
			A:   Impact_Partial,
			E:   Exploitability_Functional,
			RL:  RemediationLevel_TemporaryFix,
			RC:  ReportConfidence_Uncorroborated,
			CDP: CollateralDamagePotential_MediumHigh,
			TD:  TargetDistribution_High,
			CR:  Requirement_Medium,
			IR:  Requirement_Low,
			AR:  Requirement_Medium,
		}, "(AV:L/AC:L/Au:M/C:C/I:N/A:P/E:F/RL:T/RC:UR/CDP:MH/TD:H/CR:M/IR:L/AR:M)"},
		{BaseVectors{}, ""}, // if invalid returns empty string
	}

	for i, c := range cases {
		assert.Equal(t, c.expect, c.input.String(), "%d", i)
	}
}

func TestBaseVectorsBaseScore(t *testing.T) {
	type testcase struct {
		trg        BaseVectors
		base_score float64
		tmp_score  float64
		env_score  float64
		score      float64
	}

	var cases = []testcase{
		{BaseVectors{
			AV: AccessVector_Network,
			AC: AccessComplexity_Medium,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_None,
		}, 4.3, math.NaN(), math.NaN(), 4.3},
		{BaseVectors{
			AV: AccessVector_Network,
			AC: AccessComplexity_Low,
			Au: Authentication_None,
			C:  Impact_Partial,
			I:  Impact_Partial,
			A:  Impact_Partial,
		}, 7.5, math.NaN(), math.NaN(), 7.5},
		{BaseVectors{
			AV: AccessVector_Network,
			AC: AccessComplexity_Medium,
			Au: Authentication_Single,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_None,
		}, 3.5, math.NaN(), math.NaN(), 3.5},
		{BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_Medium,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Complete,
			A:  Impact_Complete,
		}, 6.3, math.NaN(), math.NaN(), 6.3},
		{BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_High,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_Complete,
			E:  Exploitability_ProofOfConcept,
			RL: RemediationLevel_OfficialFix,
			RC: ReportConfidence_Confirmed,
		}, 4.7, 3.7, math.NaN(), 3.7},
		{BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_Low,
			Au: Authentication_Multiple,
			C:  Impact_Complete,
			I:  Impact_None,
			A:  Impact_Partial,
			E:  Exploitability_Functional,
			RL: RemediationLevel_TemporaryFix,
			RC: ReportConfidence_Uncorroborated,
		}, 5.0, 4.1, math.NaN(), 4.1},
		{BaseVectors{
			AV:  AccessVector_Local,
			AC:  AccessComplexity_Low,
			Au:  Authentication_Multiple,
			C:   Impact_Complete,
			I:   Impact_None,
			A:   Impact_Partial,
			E:   Exploitability_Functional,
			RL:  RemediationLevel_NotDefined,
			RC:  ReportConfidence_Uncorroborated,
			CDP: CollateralDamagePotential_MediumHigh,
			TD:  TargetDistribution_High,
			CR:  Requirement_Medium,
			IR:  Requirement_Low,
			AR:  Requirement_Medium,
		}, 5.0, 4.5, 6.7, 6.7},
		{BaseVectors{
			AV:  AccessVector_Local,
			AC:  AccessComplexity_High,
			Au:  Authentication_None,
			C:   Impact_None,
			I:   Impact_Partial,
			A:   Impact_Complete,
			E:   Exploitability_ProofOfConcept,
			RL:  RemediationLevel_OfficialFix,
			RC:  ReportConfidence_Confirmed,
			CDP: CollateralDamagePotential_Low,
			TD:  TargetDistribution_Medium,
			CR:  Requirement_Low,
			IR:  Requirement_Low,
			AR:  Requirement_High,
		}, 4.7, 3.7, 4.1, 4.1},
		{BaseVectors{
			AV: AccessVector("invalid"),
			AC: AccessComplexity_Medium,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Complete,
			A:  Impact_Complete,
		}, math.NaN(), math.NaN(), math.NaN(), math.NaN()},
	}

	for i, c := range cases {
		assert.Equal(t, c.base_score, c.trg.BaseScore(), "fail on %d", i)
		assert.Equal(t, c.tmp_score, c.trg.TemporalScore(), "fail on %d", i)
		assert.Equal(t, c.env_score, c.trg.EnvironmentalScore(), "fail on %d", i)
		assert.Equal(t, c.score, c.trg.Score(), "fail on %d", i)
	}
}
