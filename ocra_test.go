//
// packager ocra package
// Author: Guido Ronchetti <guido.ronchetti@nexo.cloud>
// v1.0 16/08/2017
//

package ocra

import (
	"reflect"
	"testing"
)

var suiteTestCases = map[string]*OCRA{
	"OCRA-1:HOTP-SHA512-8:C-QN08-PSHA1": &OCRA{
		suite:     "OCRA-1:HOTP-SHA512-8:C-QN08-PSHA1",
		algorithm: 1,
		cryptoFunction: &ocraCrypto{
			mode:       cHOTPSHA512,
			truncation: 8,
		},
		dataIn: &ocraDataIn{
			questionFormat: cQuestionNumeric,
			questionSize:   8,
			counter:        true,
			password:       true,
			hashMode:       cSHA1,
			// defaults
			timeStepUnit: cTimeStampMinutes,
			timeStepSize: 1,
			sessionSize:  64,
		},
	},
	"OCRA-1:HOTP-SHA256-6:QA10-T1M": &OCRA{
		suite:     "OCRA-1:HOTP-SHA256-6:QA10-T1M",
		algorithm: 1,
		cryptoFunction: &ocraCrypto{
			mode:       cHOTPSHA256,
			truncation: 6,
		},
		dataIn: &ocraDataIn{
			questionFormat: cQuestionAlphanumeric,
			questionSize:   10,
			timeStamp:      true,
			timeStepUnit:   cTimeStampMinutes,
			timeStepSize:   1,
			// defaults
			hashMode:    cSHA1,
			sessionSize: 64,
		},
	},
	"OCRA-1:HOTP-SHA1-4:QH8-S512": &OCRA{
		suite:     "OCRA-1:HOTP-SHA1-4:QH8-S512",
		algorithm: 1,
		cryptoFunction: &ocraCrypto{
			mode:       cHOTPSHA1,
			truncation: 4,
		},
		dataIn: &ocraDataIn{
			questionFormat: cQuestionHexadecimal,
			questionSize:   8,
			session:        true,
			sessionSize:    512,
			// defaults
			timeStepUnit: cTimeStampMinutes,
			timeStepSize: 1,
			hashMode:     cSHA1,
		},
	},
	"OCRA-1:HOTP-SHA256-10:C-QH10-PSHA512-S128-T57S": &OCRA{
		suite:     "OCRA-1:HOTP-SHA256-10:C-QH10-PSHA512-S128-T57S",
		algorithm: 1,
		cryptoFunction: &ocraCrypto{
			mode:       cHOTPSHA256,
			truncation: 10,
		},
		dataIn: &ocraDataIn{
			counter:        true,
			questionFormat: cQuestionHexadecimal,
			questionSize:   10,
			password:       true,
			hashMode:       cSHA512,
			session:        true,
			sessionSize:    128,
			timeStamp:      true,
			timeStepUnit:   cTimeStampSeconds,
			timeStepSize:   57,
		},
	},
	"OCRA-1:HOTP-SHA512-6:QH10-PSHA256-T22H": &OCRA{
		suite:     "OCRA-1:HOTP-SHA512-6:QH10-PSHA256-T22H",
		algorithm: 1,
		cryptoFunction: &ocraCrypto{
			mode:       cHOTPSHA512,
			truncation: 6,
		},
		dataIn: &ocraDataIn{
			questionFormat: cQuestionHexadecimal,
			questionSize:   10,
			password:       true,
			hashMode:       cSHA256,
			sessionSize:    64,
			timeStamp:      true,
			timeStepUnit:   cTimeStampHours,
			timeStepSize:   22,
		},
	},
}

func TestNewOcra(t *testing.T) {
	for k, v := range suiteTestCases {
		instance, err := NewOCRA(k)
		if err != nil {
			t.Fatalf("Unable to create OCRA instance: %s.", err.Error())
		}
		if reflect.DeepEqual(instance, v) != true {
			t.Fatalf("Generated instance have different paramenters from reference:\n%s ->\n%#v (%#v %#v)\n!=\n%#v (%#v %#v).",
				k, instance, instance.cryptoFunction, instance.dataIn,
				v, v.cryptoFunction, v.dataIn,
			)
		}
	}
}

var malformedSuitesTestCases = []string{
	"OCRA-1:HOTP-SHA512-6:QH10-PSHA256-T22L",
	"OCRA-1:HOTP-SHA512-6:T22M-QH10-PSHA256",
	"OCRA-1:HOTP-SHA512-6:C-C-QH10-PSHA256",
	"OCRA-1:HOTP-SHA51223-6:C-QH10",
	"OCRA-1:HOTP-SHA512-6:C",
	"OCRA-1:HOTP-SHA512-6",
	"OCRA-1:HOTP-SHA512-623:C-QN8",
	"OCRA-12:HOTP-SHA512-6:C-QN8",
	"CCRA-1:HOTP-SHA512-6:C-QN8",
	"OCRA-1:HOTP-SHA-6:C-QN8",
	"",
	":::",
}

func TestNewOcraWithMalformedSuite(t *testing.T) {
	for _, value := range malformedSuitesTestCases {
		_, err := NewOCRA(value)
		if err == nil {
			t.Fatalf("Malformed suite %s should be detected by regex evaluation.", value)
		}
	}
}
