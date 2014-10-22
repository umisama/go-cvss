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
	submatches := regexp.MustCompile(`\(AV:([LAN])\/AC:([HML])\/Au:([NSM])\/C:([NPC])\/I:([NPC])\/A:([NPC])(?:\/E:(ND|U|POC|F|H)\/RL:(ND|OF|T|W|U)\/RC:(ND|UC|UR|C)(?:\/CDP:(N|L|LM|MH|H|ND)\/TD:(N|L|M|H|ND)\/CR:(L|M|H|ND)\/IR:(L|M|H|ND)\/AR:(L|M|H|ND))?)?\)`).FindStringSubmatch(str)
	if len(submatches) != 15 || submatches[0] != str {
		return BaseVectors{}, fmt.Errorf("invalid vectors string: %s", str)
	}

	m := BaseVectors{
		AV:  AccessVector(submatches[1]),
		AC:  AccessComplexity(submatches[2]),
		Au:  Authentication(submatches[3]),
		C:   Impact(submatches[4]),
		I:   Impact(submatches[5]),
		A:   Impact(submatches[6]),
		E:   Exploitability(submatches[7]),
		RL:  RemediationLevel(submatches[8]),
		RC:  ReportConfidence(submatches[9]),
		CDP: CollateralDamagePotential(submatches[10]),
		TD:  TargetDistribution(submatches[11]),
		CR:  Requirement(submatches[12]),
		IR:  Requirement(submatches[13]),
		AR:  Requirement(submatches[14]),
	}
	if !m.IsValid() {
		return BaseVectors{}, fmt.Errorf("invalid vectors string: %s", str)
	}

	return m, nil
}

func (m BaseVectors) BaseScore() float64 {
	return round(m.baseScore())
}

func (m BaseVectors) baseScore() float64 {
	if !m.IsValid() {
		return math.NaN()
	}

	impact := m.impact()
	exploitability := m.exploitability()
	impact_sub := iif(impact == 0.0, 0.0, 1.176)
	base_score := ((0.6 * impact) + (0.4 * exploitability) - 1.5) * impact_sub
	return base_score
}

func (m BaseVectors) Impact() float64 {
	return round(m.impact())
}

func (m BaseVectors) impact() float64 {
	return 10.41 * (1 - (1-m.C.Score())*(1-m.I.Score())*(1-m.A.Score()))
}

func (m BaseVectors) Exploitability() float64 {
	return round(m.exploitability())
}

func (m BaseVectors) exploitability() float64 {
	return 20 * m.AV.Score() * m.AC.Score() * m.Au.Score()
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

func iif(cond bool, t, f float64) float64 {
	if cond {
		return t
	}
	return f
}
