# umisama/go-cvss[![Build Status](https://travis-ci.org/umisama/go-cvss.svg?branch=master)](https://travis-ci.org/umisama/go-cvss)
A Common Vulnerability Scoring System 2.0 (CVSSv2) implementation for golang.

## status
complete.

## intallation
off cource, go getable
```
go get github.com/umisama/go-cvss
``` 

## usage
simple example is here
```go
import "github.com/umisama/go-cvss"


// Create vector with formated string.
v, err := cvss.ParseVectors(
        "(AV:L/AC:H/Au:N/C:N/I:P/A:C)")
if err != nil {
        panic(err) // if string is invalid.
}
fmt.Printf("string: %s \n", v.String())
fmt.Printf(
        "base_score: %f  / temporal_score: %f / environment_score: %f\noverall %f\n\n",
        v.BaseScore(), v.TemporalScore(), v.EnvironmentalScore(), v.Score())

// Supporting temporal/environment vectors.
v, err = cvss.ParseVectors(
        "(AV:L/AC:H/Au:N/C:N/I:P/A:C/E:POC/RL:OF/RC:C/CDP:L/TD:M/CR:L/IR:L/AR:H)")
if err != nil {
        panic(err) // if string is invalid.
}
fmt.Printf("string: %s \n", v.String())
fmt.Printf(
        "base_score: %f  / temporal_score: %f / environment_score: %f\noverall %f\n\n",
        v.BaseScore(), v.TemporalScore(), v.EnvironmentalScore(), v.Score())

// You can create struct directly.
v = cvss.Vectors{
        AV:  cvss.AccessVector_Local,
        AC:  cvss.AccessComplexity_High,
        Au:  cvss.Authentication_None,
        C:   cvss.Impact_None,
        I:   cvss.Impact_Partial,
        A:   cvss.Impact_Complete,
        E:   cvss.Exploitability_ProofOfConcept,
        RL:  cvss.RemediationLevel_OfficialFix,
        RC:  cvss.ReportConfidence_Confirmed,
        CDP: cvss.CollateralDamagePotential_Low,
        TD:  cvss.TargetDistribution_Medium,
        CR:  cvss.Requirement_Low,
        IR:  cvss.Requirement_Low,
        AR:  cvss.Requirement_High,
}
fmt.Printf("string: %s \n", v.String())
fmt.Printf(
        "base_score: %f  / temporal_score: %f / environment_score: %f\noverall %f\n\n",
        v.BaseScore(), v.TemporalScore(), v.EnvironmentalScore(), v.Score())
```

## document
 * [godoc.org](http://godoc.org/github.com/umisama/go-cvss)

## reference
 * [NVD - CVSS v2 Vector Definitions](http://nvd.nist.gov/CVSS/Vector-v2.aspx)
 * [A Complete Guide to the Common Vulnerability Scoring System Version 2.0](http://www.first.org/cvss/cvss-guide.html)

## license
under the MIT License
