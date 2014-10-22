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
