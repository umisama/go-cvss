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
	if !m.isValid() {
		return Vectors{}, fmt.Errorf("invalid vectors string: %s", str)
	}

	return m, nil
}

func (m Vectors) BaseScore() float64 {
	return m.baseScore(m.impact())
}

func (m Vectors) baseScore(impact float64) float64 {
	if !m.isValid() {
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
	return 10.41 * (1 - (1-m.C.score())*(1-m.I.score())*(1-m.A.score()))
}

func (m Vectors) ExploitabilitySubScore() float64 {
	return round(m.exploitability())
}

func (m Vectors) exploitability() float64 {
	return 20 * m.AV.score() * m.AC.score() * m.Au.score()
}

func (m Vectors) TemporalScore() float64 {
	return m.temporalScore(m.baseScore(m.impact()))
}

func (m Vectors) temporalScore(base float64) float64 {
	if !m.HasTemporalVectors() {
		return math.NaN()
	}

	return round(base * m.E.score() * m.RL.score() * m.RC.score())
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

	return (atemporal + (10-atemporal)*m.CDP.score()) * m.TD.score()
}

func (m Vectors) AdjustedImpactSubScore() float64 {
	return round(m.adjustedImpactSubScore())
}

func (m Vectors) adjustedImpactSubScore() float64 {
	if !m.HasEnvironmentalVectors() {
		return math.NaN()
	}

	score := 10.41 * (1 - (1-m.C.score()*m.CR.score())*(1-m.I.score()*m.IR.score())*(1-m.A.score()*m.AR.score()))
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

func (m Vectors) isValid() bool {
	return m.A.isValid() && m.AC.isValid() && m.Au.isValid() && m.AV.isValid() &&
		m.C.isValid() && m.I.isValid() && m.E.isValid() && m.RL.isValid() && m.RC.isValid() &&
		m.CDP.isValid() && m.TD.isValid() && m.CR.isValid() && m.IR.isValid() && m.AR.isValid()
}

func (m Vectors) HasEnvironmentalVectors() bool {
	return m.CDP.isDefined() || m.TD.isDefined() || m.CR.isDefined() ||
		m.IR.isDefined() || m.AR.isDefined()
}

func (m Vectors) HasTemporalVectors() bool {
	return m.HasEnvironmentalVectors() || m.E.isDefined() || m.RL.isDefined() || m.RC.isDefined()
}

func (m Vectors) String() string {
	if !m.isValid() {
		return ""
	}

	base := "AV:" + m.AV.stringShort() + "/AC:" + m.AC.stringShort() + "/Au:" + m.Au.stringShort() +
		"/C:" + m.C.stringShort() + "/I:" + m.I.stringShort() + "/A:" + m.A.stringShort()
	temporary := ""
	environment := ""
	if m.HasTemporalVectors() {
		temporary = "/E:" + m.E.stringShort() + "/RL:" + m.RL.stringShort() + "/RC:" + m.RC.stringShort()
	}
	if m.HasEnvironmentalVectors() {
		environment = "/CDP:" + m.CDP.stringShort() + "/TD:" + m.TD.stringShort() + "/CR:" + m.CR.stringShort() + "/IR:" + m.IR.stringShort() + "/AR:" + m.AR.stringShort()
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
