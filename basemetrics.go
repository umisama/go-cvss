package cvss

import (
	"fmt"
	"math"
	"regexp"
)

type BaseVectors struct {
	AV AccessVector
	AC AccessComplexity
	Au Authentication
	C  Impact
	I  Impact
	A  Impact
}

type MetricsFactor interface {
	IsValid() bool
	Score() float64
	String() string
	StringShort() string
}

type AccessVector string
type AccessComplexity string
type Authentication string
type Impact string

const (
	AccessVector_Local           = AccessVector("L")
	AccessVector_AdjacentNetwork = AccessVector("A")
	AccessVector_Network         = AccessVector("N")
	AccessComplexity_High        = AccessComplexity("H")
	AccessComplexity_Midium      = AccessComplexity("M")
	AccessComplexity_Low         = AccessComplexity("L")
	Authentication_Multiple      = Authentication("M")
	Authentication_Single        = Authentication("S")
	Authentication_None          = Authentication("N")
	Impact_Complete        = Impact("C")
	Impact_Partial         = Impact("P")
	Impact_None            = Impact("N")
)

func (m AccessVector) IsValid() bool {
	return m == AccessVector_Local ||
		m == AccessVector_AdjacentNetwork ||
		m == AccessVector_Network
}

func (m AccessVector) Score() float64 {
	switch m {
	case AccessVector_Local:
		return 0.395
	case AccessVector_AdjacentNetwork:
		return 0.646
	case AccessVector_Network:
		return 1.0
	}

	return math.NaN()
}

func (m AccessVector) String() string {
	switch m {
	case AccessVector_Local:
		return "Local"
	case AccessVector_AdjacentNetwork:
		return "Adjacent Network"
	case AccessVector_Network:
		return "Network"
	}

	return ""
}

func (m AccessVector) StringShort() string {
	switch m {
	case AccessVector_Local, AccessVector_AdjacentNetwork, AccessVector_Network:
		return string(m)
	}

	return ""
}

func (m AccessComplexity) IsValid() bool {
	return m == AccessComplexity_High ||
		m == AccessComplexity_Midium ||
		m == AccessComplexity_Low
}

func (m AccessComplexity) Score() float64 {
	switch m {
	case AccessComplexity_High:
		return 0.35
	case AccessComplexity_Midium:
		return 0.61
	case AccessComplexity_Low:
		return 0.71
	}

	return math.NaN()
}

func (m AccessComplexity) String() string {
	switch m {
	case AccessComplexity_High:
		return "High"
	case AccessComplexity_Midium:
		return "Midium"
	case AccessComplexity_Low:
		return "Low"
	}

	return ""
}

func (m AccessComplexity) StringShort() string {
	switch m {
	case AccessComplexity_High, AccessComplexity_Midium, AccessComplexity_Low:
		return string(m)
	}

	return ""
}

func (m Authentication) IsValid() bool {
	return m == Authentication_Multiple ||
		m == Authentication_Single ||
		m == Authentication_None
}

func (m Authentication) Score() float64 {
	switch m {
	case Authentication_Multiple:
		return 0.45
	case Authentication_Single:
		return 0.56
	case Authentication_None:
		return 0.704
	}

	return math.NaN()
}

func (m Authentication) String() string {
	switch m {
	case Authentication_Multiple:
		return "Multiple"
	case Authentication_Single:
		return "Single"
	case Authentication_None:
		return "None"
	}

	return ""
}

func (m Authentication) StringShort() string {
	switch m {
	case Authentication_Multiple, Authentication_Single, Authentication_None:
		return string(m)
	}

	return ""
}

func (m Impact) IsValid() bool {
	return m == Impact_Complete ||
		m == Impact_Partial ||
		m == Impact_None
}

func (m Impact) Score() float64 {
	switch m {
	case Impact_Complete:
		return 0.660
	case Impact_Partial:
		return 0.275
	case Impact_None:
		return 0.0
	}

	return math.NaN()
}

func (m Impact) String() string {
	switch m {
	case Impact_Complete:
		return "Complete"
	case Impact_Partial:
		return "Partial"
	case Impact_None:
		return "None"
	}

	return ""
}

func (m Impact) StringShort() string {
	switch m {
	case Impact_Complete, Impact_Partial, Impact_None:
		return string(m)
	}

	return ""
}

func ParseBaseVectors(str string) (BaseVectors, error) {
	submatches := regexp.MustCompile(`\(AV:([LAN])\/AC:([HML])\/Au:([NSM])\/C:([NPC])\/I:([NPC])\/A:([NPC])\)`).FindStringSubmatch(str)
	if len(submatches) != 7 || submatches[0] != str {
		return BaseVectors{}, fmt.Errorf("invalid base vectors string: %s", str)
	}

	m := BaseVectors{
		AV: AccessVector(submatches[1]),
		AC: AccessComplexity(submatches[2]),
		Au: Authentication(submatches[3]),
		C: Impact(submatches[4]),
		I: Impact(submatches[5]),
		A: Impact(submatches[6]),
	}
	if !m.IsValid() {
		return BaseVectors{}, fmt.Errorf("invalid base vectors string: %s", str)
	}

	return m, nil
}

func (m BaseVectors) BaseScore() float64 {
	if !m.IsValid() {
		return math.NaN()
	}

	easyly_score := 20 * m.AV.Score() * m.AC.Score() * m.Au.Score()
	effective_score := 10.41 * (1 - (1-m.C.Score())*(1-m.I.Score())*(1-m.A.Score()))
	effective_score_sub := 0.0
	if effective_score != 0 {
		effective_score_sub = 1.176
	}

	base_score := ((0.6 * effective_score) + (0.4 * easyly_score) - 1.5) * effective_score_sub
	return round(base_score)
}

func (m BaseVectors) IsValid() bool {
	return m.A.IsValid() && m.AC.IsValid() && m.Au.IsValid() && m.AV.IsValid() && m.C.IsValid() && m.I.IsValid()
}

func (m BaseVectors) String() string {
	if !m.IsValid() {
		return ""
	}





	return "strings"
}

func round(val float64) float64 {
	digit := val * 10
	_, frac := math.Modf(digit)

	if frac >= 0.5 {
		return math.Ceil(digit) / 10
	} else {
		return math.Floor(digit) / 10
	}
}
