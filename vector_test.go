package cvss

import (
	"github.com/stretchr/testify/assert"
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
			AV: AccessVector_Local,
			AC: AccessComplexity_High,
			Au: Authentication_None,
			C:  Impact_None,
			I:  Impact_Partial,
			A:  Impact_Complete,
			E:  Exploitability_ProofOfConcept,
			RL: RemediationLevel_OfficialFix,
			RC: ReportConfidence_Confirmed,
			CDP: CollateralDamagePotential_Low,
			TD: TargetDistribution_Medium,
			CR: Requirement_Low,
			IR: Requirement_Low,
			AR: Requirement_High,
		}, false},
		{"(AV:L/AC:L/Au:M/C:C/I:N/A:P/E:F/RL:T/RC:UR/CDP:MH/TD:H/CR:M/IR:L/AR:M)", BaseVectors{
			AV: AccessVector_Local,
			AC: AccessComplexity_Low,
			Au: Authentication_Multiple,
			C:  Impact_Complete,
			I:  Impact_None,
			A:  Impact_Partial,
			E:  Exploitability_Functional,
			RL: RemediationLevel_TemporaryFix,
			RC: ReportConfidence_Uncorroborated,
			CDP: CollateralDamagePotential_MediumHigh,
			TD: TargetDistribution_High,
			CR: Requirement_Medium,
			IR: Requirement_Low,
			AR: Requirement_Medium,
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
		{BaseVectors{}, ""}, // if invalid returns empty string
	}

	for i, c := range cases {
		assert.Equal(t, c.expect, c.input.String(), "%d", i)
	}
}
