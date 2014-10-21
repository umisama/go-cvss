# umisama/go-cvss[![Build Status](https://travis-ci.org/umisama/cvss.svg?branch=master)](https://travis-ci.org/umisama/cvss)
A Common Vulnerability Scoring System implementation for golang.

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

## license
under the MIT License
