package cvss

import (
	"fmt"
	"math"
	"regexp"
)

type Vectors struct {
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

func ParseVectors(str string) (Vectors, error) {
	submatches := regexp.MustCompile(`\(AV:([LAN])\/AC:([HML])\/Au:([NSM])\/C:([NPC])\/I:([NPC])\/A:([NPC])(?:\/E:(ND|U|POC|F|H)\/RL:(ND|OF|T|W|U)\/RC:(ND|UC|UR|C)(?:\/CDP:(N|L|LM|MH|H|ND)\/TD:(N|L|M|H|ND)\/CR:(L|M|H|ND)\/IR:(L|M|H|ND)\/AR:(L|M|H|ND))?)?\)`).FindStringSubmatch(str)
	if len(submatches) != 15 || submatches[0] != str {
		return Vectors{}, fmt.Errorf("invalid vectors string: %s", str)
	}

	m := Vectors{
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
		return Vectors{}, fmt.Errorf("invalid vectors string: %s", str)
	}

	return m, nil
}

func (m Vectors) BaseScore() float64 {
	return m.baseScore(m.impact())
}

func (m Vectors) baseScore(impact float64) float64 {
	if !m.IsValid() {
		return math.NaN()
	}

	exploitability := m.exploitability()
	impact_sub := iif(impact == 0.0, 0.0, 1.176)
	base_score := ((0.6 * impact) + (0.4 * exploitability) - 1.5) * impact_sub
	return round(base_score)
}

func (m Vectors) ImpactSubScore() float64 {
	return round(m.impact())
}

func (m Vectors) impact() float64 {
	return 10.41 * (1 - (1-m.C.Score())*(1-m.I.Score())*(1-m.A.Score()))
}

func (m Vectors) ExploitabilitySubScore() float64 {
	return round(m.exploitability())
}

func (m Vectors) exploitability() float64 {
	return 20 * m.AV.Score() * m.AC.Score() * m.Au.Score()
}

func (m Vectors) TemporalScore() float64 {
	return m.temporalScore(m.baseScore(m.impact()))
}

func (m Vectors) temporalScore(base float64) float64 {
	if !m.HasTemporalVectors() {
		return math.NaN()
	}

	return round(base * m.E.Score() * m.RL.Score() * m.RC.Score())
}

func (m Vectors) EnvironmentalScore() float64 {
	return round(m.environmentalScore())
}

func (m Vectors) environmentalScore() float64 {
	if !m.HasEnvironmentalVectors() {
		return math.NaN()
	}

	aimpact := m.adjustedImpactSubScore()
	atemporal := m.temporalScore(m.baseScore(aimpact))

	return (atemporal + (10-atemporal)*m.CDP.Score()) * m.TD.Score()
}

func (m Vectors) AdjustedImpactSubScore() float64 {
	return round(m.adjustedImpactSubScore())
}

func (m Vectors) adjustedImpactSubScore() float64 {
	if !m.HasEnvironmentalVectors() {
		return math.NaN()
	}

	score := 10.41 * (1 - (1-m.C.Score()*m.CR.Score())*(1-m.I.Score()*m.IR.Score())*(1-m.A.Score()*m.AR.Score()))
	if score > 10.00 {
		return 10.00
	}
	return score
}

func (m Vectors) Score() float64 {
	if !math.IsNaN(m.EnvironmentalScore()) {
		return m.EnvironmentalScore()
	}
	if !math.IsNaN(m.TemporalScore()) {
		return m.TemporalScore()
	}
	if !math.IsNaN(m.BaseScore()) {
		return m.BaseScore()
	}
	return math.NaN()
}

func (m Vectors) IsValid() bool {
	return m.A.IsValid() && m.AC.IsValid() && m.Au.IsValid() && m.AV.IsValid() &&
		m.C.IsValid() && m.I.IsValid() && m.E.IsValid() && m.RL.IsValid() && m.RC.IsValid() &&
		m.CDP.IsValid() && m.TD.IsValid() && m.CR.IsValid() && m.IR.IsValid() && m.AR.IsValid()
}

func (m Vectors) HasEnvironmentalVectors() bool {
	return m.CDP.IsDefined() || m.TD.IsDefined() || m.CR.IsDefined() ||
		m.IR.IsDefined() || m.AR.IsDefined()
}

func (m Vectors) HasTemporalVectors() bool {
	return m.HasEnvironmentalVectors() || m.E.IsDefined() || m.RL.IsDefined() || m.RC.IsDefined()
}

func (m Vectors) String() string {
	if !m.IsValid() {
		return ""
	}

	base := "AV:" + m.AV.StringShort() + "/AC:" + m.AC.StringShort() + "/Au:" + m.Au.StringShort() +
		"/C:" + m.C.StringShort() + "/I:" + m.I.StringShort() + "/A:" + m.A.StringShort()
	temporary := ""
	environment := ""
	if m.HasTemporalVectors() {
		temporary = "/E:" + m.E.StringShort() + "/RL:" + m.RL.StringShort() + "/RC:" + m.RC.StringShort()
	}
	if m.HasEnvironmentalVectors() {
		environment = "/CDP:" + m.CDP.StringShort() + "/TD:" + m.TD.StringShort() + "/CR:" + m.CR.StringShort() + "/IR:" + m.IR.StringShort() + "/AR:" + m.AR.StringShort()
	}

	return "(" + base + temporary + environment + ")"
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
