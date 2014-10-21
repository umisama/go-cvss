# umisama/go-cvss[![Build Status](https://travis-ci.org/umisama/cvss.svg?branch=master)](https://travis-ci.org/umisama/cvss)
A Common Vulnerability Scoring System 2.0 implementation for golang.

## status
Supporting only CVSS Base vectors now.  
I have plan to support CVSS Temporal vectors and Emvironmental vectors.

## intallation
off cource, go getable
```
go get github.com/umisama/go-cvss
``` 

## usage
simple example is here
```go
// Create BaseVectors with formated string.
bv, err := cvss.ParseBaseVectors("(AV:L/AC:H/Au:N/C:N/I:P/A:C)")
if err != nil {
	panic(err) // invalid string
}

// show values
fmt.Println("base score is :", bv.BaseScore())
fmt.Println("vector string:", bv)
```

## reference
 * [NVD - CVSS v2 Vector Definitions](http://nvd.nist.gov/CVSS/Vector-v2.aspx)
 * [A Complete Guide to the Common Vulnerability Scoring System Version 2.0](http://www.first.org/cvss/cvss-guide.html)

## license
under the MIT License
