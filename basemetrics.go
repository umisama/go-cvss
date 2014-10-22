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
type Exploitability string
type RemediationLevel string
type ReportConfidence string
type CollateralDamagePotential string
type TargetDistribution string
type Requirement string

const (
	AccessVector_Local                   = AccessVector("L")
	AccessVector_AdjacentNetwork         = AccessVector("A")
	AccessVector_Network                 = AccessVector("N")
	AccessComplexity_High                = AccessComplexity("H")
	AccessComplexity_Medium              = AccessComplexity("M")
	AccessComplexity_Low                 = AccessComplexity("L")
	Authentication_Multiple              = Authentication("M")
	Authentication_Single                = Authentication("S")
	Authentication_None                  = Authentication("N")
	Impact_Complete                      = Impact("C")
	Impact_Partial                       = Impact("P")
	Impact_None                          = Impact("N")
	Exploitability_Unproven              = Exploitability("U")
	Exploitability_ProofOfConcept        = Exploitability("POC")
	Exploitability_Functional            = Exploitability("F")
	Exploitability_High                  = Exploitability("H")
	Exploitability_NotDefined            = Exploitability("ND")
	RemediationLevel_OfficialFix         = RemediationLevel("OF")
	RemediationLevel_TemporaryFix        = RemediationLevel("T")
	RemediationLevel_Workaround          = RemediationLevel("W")
	RemediationLevel_Unavailable         = RemediationLevel("U")
	RemediationLevel_NotDefined          = RemediationLevel("ND")
	ReportConfidence_Unconfirmed         = ReportConfidence("UC")
	ReportConfidence_Uncorroborated      = ReportConfidence("UR")
	ReportConfidence_Confirmed           = ReportConfidence("C")
	ReportConfidence_NotDefined          = ReportConfidence("ND")
	CollateralDamagePotential_None       = CollateralDamagePotential("N")
	CollateralDamagePotential_Low        = CollateralDamagePotential("L")
	CollateralDamagePotential_LowMedium  = CollateralDamagePotential("LM")
	CollateralDamagePotential_MediumHigh = CollateralDamagePotential("MH")
	CollateralDamagePotential_High       = CollateralDamagePotential("H")
	CollateralDamagePotential_NotDefined = CollateralDamagePotential("ND")
	TargetDistribution_None              = TargetDistribution("N")
	TargetDistribution_Low               = TargetDistribution("L")
	TargetDistribution_Medium            = TargetDistribution("M")
	TargetDistribution_High              = TargetDistribution("H")
	TargetDistribution_NotDefined        = TargetDistribution("ND")
	Requirement_Low                      = Requirement("L")
	Requirement_Medium                   = Requirement("M")
	Requirement_High                     = Requirement("H")
	Requirement_NotDefined               = Requirement("ND")
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
		m == AccessComplexity_Medium ||
		m == AccessComplexity_Low
}

func (m AccessComplexity) Score() float64 {
	switch m {
	case AccessComplexity_High:
		return 0.35
	case AccessComplexity_Medium:
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
	case AccessComplexity_Medium:
		return "Medium"
	case AccessComplexity_Low:
		return "Low"
	}

	return ""
}

func (m AccessComplexity) StringShort() string {
	switch m {
	case AccessComplexity_High, AccessComplexity_Medium, AccessComplexity_Low:
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

func (m Exploitability) IsValid() bool {
	return m == Exploitability_Unproven ||
		m == Exploitability_ProofOfConcept ||
		m == Exploitability_Functional ||
		m == Exploitability_High
}

func (m Exploitability) Score() float64 {
	switch m {
	case Exploitability_Unproven:
		return 0.85
	case Exploitability_ProofOfConcept:
		return 0.9
	case Exploitability_Functional:
		return 0.95
	case Exploitability_High:
		return 1.00
	case Exploitability_NotDefined, Exploitability(""):
		return 1.00
	}

	return math.NaN()
}

func (m Exploitability) String() string {
	switch m {
	case Exploitability_Unproven:
		return "Unproven"
	case Exploitability_ProofOfConcept:
		return "Proof-of-concept"
	case Exploitability_Functional:
		return "Functional"
	case Exploitability_High:
		return "High"
	case Exploitability_NotDefined, Exploitability(""):
		return "Not Defined"
	}

	return ""
}

func (m Exploitability) StringShort() string {
	switch m {
	case Exploitability_Unproven, Exploitability_ProofOfConcept, Exploitability_Functional, Exploitability_High, Exploitability_NotDefined:
		return string(m)
	case Exploitability(""):
		return string(Exploitability_NotDefined)
	}

	return ""
}

func (m RemediationLevel) IsValid() bool {
	return m == RemediationLevel_OfficialFix ||
		m == RemediationLevel_TemporaryFix ||
		m == RemediationLevel_Workaround ||
		m == RemediationLevel_Unavailable
}

func (m RemediationLevel) Score() float64 {
	switch m {
	case RemediationLevel_OfficialFix:
		return 0.87
	case RemediationLevel_TemporaryFix:
		return 0.90
	case RemediationLevel_Workaround:
		return 0.95
	case RemediationLevel_Unavailable:
		return 1.00
	case RemediationLevel_NotDefined, RemediationLevel(""):
		return 1.00
	}

	return math.NaN()
}

func (m RemediationLevel) String() string {
	switch m {
	case RemediationLevel_OfficialFix:
		return "Official-fix"
	case RemediationLevel_TemporaryFix:
		return "Temporary-fix"
	case RemediationLevel_Workaround:
		return "Workaround"
	case RemediationLevel_Unavailable:
		return "Unavailable"
	case RemediationLevel_NotDefined, RemediationLevel(""):
		return "Not Defined"
	}

	return ""
}

func (m RemediationLevel) StringShort() string {
	switch m {
	case RemediationLevel_OfficialFix, RemediationLevel_TemporaryFix, RemediationLevel_Workaround, RemediationLevel_Unavailable, RemediationLevel_NotDefined:
		return string(m)
	case RemediationLevel(""):
		return string(RemediationLevel_NotDefined)
	}

	return ""
}

func (m ReportConfidence) IsValid() bool {
	return m == ReportConfidence_Unconfirmed ||
		m == ReportConfidence_Uncorroborated ||
		m == ReportConfidence_Confirmed
}

func (m ReportConfidence) Score() float64 {
	switch m {
	case ReportConfidence_Unconfirmed:
		return 0.90
	case ReportConfidence_Uncorroborated:
		return 0.95
	case ReportConfidence_Confirmed:
		return 1.00
	case ReportConfidence_NotDefined, ReportConfidence(""):
		return 1.00
	}

	return math.NaN()
}

func (m ReportConfidence) String() string {
	switch m {
	case ReportConfidence_Unconfirmed:
		return "Unconfirmed"
	case ReportConfidence_Uncorroborated:
		return "Uncorroborated"
	case ReportConfidence_Confirmed:
		return "Confirmed"
	case ReportConfidence_NotDefined, ReportConfidence(""):
		return "Not Defined"
	}

	return ""
}

func (m ReportConfidence) StringShort() string {
	switch m {
	case ReportConfidence_Confirmed, ReportConfidence_Unconfirmed, ReportConfidence_Uncorroborated, ReportConfidence_NotDefined:
		return string(m)
	case ReportConfidence(""):
		return string(ReportConfidence_NotDefined)
	}

	return ""
}

func (m CollateralDamagePotential) IsValid() bool {
	return m == CollateralDamagePotential_None ||
		m == CollateralDamagePotential_Low ||
		m == CollateralDamagePotential_LowMedium ||
		m == CollateralDamagePotential_MediumHigh ||
		m == CollateralDamagePotential_High

}

func (m CollateralDamagePotential) Score() float64 {
	switch m {
	case CollateralDamagePotential_None:
		return 0.00
	case CollateralDamagePotential_Low:
		return 0.10
	case CollateralDamagePotential_LowMedium:
		return 0.30
	case CollateralDamagePotential_MediumHigh:
		return 0.40
	case CollateralDamagePotential_High:
		return 0.50
	case CollateralDamagePotential_NotDefined, CollateralDamagePotential(""):
		return 0.00
	}

	return math.NaN()
}

func (m CollateralDamagePotential) String() string {
	switch m {
	case CollateralDamagePotential_None:
		return "None"
	case CollateralDamagePotential_Low:
		return "Low"
	case CollateralDamagePotential_LowMedium:
		return "Low-Medium"
	case CollateralDamagePotential_MediumHigh:
		return "Medium-High"
	case CollateralDamagePotential_High:
		return "High"
	case CollateralDamagePotential_NotDefined, CollateralDamagePotential(""):
		return "Not Defined"
	}

	return ""
}

func (m CollateralDamagePotential) StringShort() string {
	switch m {
	case CollateralDamagePotential_Low, CollateralDamagePotential_LowMedium, CollateralDamagePotential_MediumHigh, CollateralDamagePotential_High, CollateralDamagePotential_None, CollateralDamagePotential_NotDefined:
		return string(m)
	case CollateralDamagePotential(""):
		return string(CollateralDamagePotential_NotDefined)
	}

	return ""
}

func (m TargetDistribution) IsValid() bool {
	return m == TargetDistribution_None ||
		m == TargetDistribution_Low ||
		m == TargetDistribution_Medium ||
		m == TargetDistribution_High
}

func (m TargetDistribution) Score() float64 {
	switch m {
	case TargetDistribution_None:
		return 0.00
	case TargetDistribution_Low:
		return 0.25
	case TargetDistribution_Medium:
		return 0.75
	case TargetDistribution_High:
		return 1.00
	case TargetDistribution_NotDefined, TargetDistribution(""):
		return 1.00
	}

	return math.NaN()
}

func (m TargetDistribution) String() string {
	switch m {
	case TargetDistribution_None:
		return "None"
	case TargetDistribution_Low:
		return "Low"
	case TargetDistribution_Medium:
		return "Medium"
	case TargetDistribution_High:
		return "High"
	case TargetDistribution_NotDefined, TargetDistribution(""):
		return "Not Defined"
	}

	return ""
}

func (m TargetDistribution) StringShort() string {
	switch m {
	case TargetDistribution_Low, TargetDistribution_Medium, TargetDistribution_High, TargetDistribution_None, TargetDistribution_NotDefined:
		return string(m)
	case TargetDistribution(""):
		return string(TargetDistribution_NotDefined)
	}

	return ""
}

func (m Requirement) IsValid() bool {
	return m == Requirement_Low ||
		m == Requirement_Medium ||
		m == Requirement_High
}

func (m Requirement) Score() float64 {
	switch m {
	case Requirement_Low:
		return 0.50
	case Requirement_Medium:
		return 1.00
	case Requirement_High:
		return 1.51
	case Requirement_NotDefined, Requirement(""):
		return 1.00
	}

	return math.NaN()
}

func (m Requirement) String() string {
	switch m {
	case Requirement_Low:
		return "Low"
	case Requirement_Medium:
		return "Medium"
	case Requirement_High:
		return "High"
	case Requirement_NotDefined, Requirement(""):
		return "Not Defined"
	}

	return ""
}

func (m Requirement) StringShort() string {
	switch m {
	case Requirement_Low, Requirement_Medium, Requirement_High, Requirement_NotDefined:
		return string(m)
	case Requirement(""):
		return string(Requirement_NotDefined)
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
