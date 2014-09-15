package cvss

import (
	"math"
)

type BaseMetrics struct {
	Av AccessVector
	Ac AccessComplexity
	Au Authentication
	C  ImpactMetric
	I  ImpactMetric
	A  ImpactMetric
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
type ImpactMetric string

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
	ImpactMetric_Complete        = ImpactMetric("C")
	ImpactMetric_Partial         = ImpactMetric("P")
	ImpactMetric_None            = ImpactMetric("N")
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

func (m ImpactMetric) IsValid() bool {
	return m == ImpactMetric_Complete ||
		m == ImpactMetric_Partial ||
		m == ImpactMetric_None
}

func (m ImpactMetric) Score() float64 {
	switch m {
	case ImpactMetric_Complete:
		return 0.660
	case ImpactMetric_Partial:
		return 0.275
	case ImpactMetric_None:
		return 0.0
	}

	return math.NaN()
}

func (m ImpactMetric) String() string {
	switch m {
	case ImpactMetric_Complete:
		return "Complete"
	case ImpactMetric_Partial:
		return "Partial"
	case ImpactMetric_None:
		return "None"
	}

	return ""
}

func (m ImpactMetric) StringShort() string {
	switch m {
	case ImpactMetric_Complete, ImpactMetric_Partial, ImpactMetric_None:
		return string(m)
	}

	return ""
}

func (m BaseMetrics) BaseScore() float64 {
	if !m.IsValid() {
		return math.NaN()
	}

	easyly_score := 20 * m.Av.Score() * m.Ac.Score() * m.Au.Score()
	effective_score := 10.41 * (1 - (1-m.C.Score())*(1-m.I.Score())*(1-m.A.Score()))
	effective_score_sub := 0.0
	if effective_score != 0 {
		effective_score_sub = 1.176
	}

	base_score := ((0.6 * effective_score) + (0.4 * easyly_score) - 1.5) * effective_score_sub
	return round(base_score)
}

func (m BaseMetrics) IsValid() bool {
	return m.A.IsValid() && m.Ac.IsValid() && m.Au.IsValid() && m.Av.IsValid() && m.C.IsValid() && m.I.IsValid()
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
