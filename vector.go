package cvss

import (
	"fmt"
	"math"
	"regexp"
)

type BaseVectors struct {
	AV  AccessVector
	AC  AccessComplexity
	Au  Authentication
	C   Impact
	I   Impact
	A   Impact
	E   Exploitability
	RL  RemediationLevel
	RC  ReportConfidence
	CDP CollateralDamagePotential
	TD  TargetDistribution
	CR  Requirement
	IR  Requirement
	AR  Requirement
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
		C:  Impact(submatches[4]),
		I:  Impact(submatches[5]),
		A:  Impact(submatches[6]),
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

	return "(AV:" + m.AV.StringShort() + "/AC:" + m.AC.StringShort() + "/Au:" + m.Au.StringShort() +
		"/C:" + m.C.StringShort() + "/I:" + m.I.StringShort() + "/A:" + m.A.StringShort() + ")"
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
