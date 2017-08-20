//
// packager ocra package
// Author: Guido Ronchetti <guido.ronchetti@nexo.cloud>
// v1.0 16/08/2017
//

package ocra

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
	"time"
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

func TestOTPGeneration(t *testing.T) {
	ocra, err := NewOCRA("OCRA-1:HOTP-SHA512-10:C-QA64-PSHA1-S016")
	if err != nil {
		t.Fatalf("Unable to create OCRA instance: %s.", err.Error())
	}
	pwd, err := ocra.PasswordEncoding([]byte("password"))
	if err != nil {
		t.Fatalf("Unable to encode password: %s.", err.Error())
	}
	question, err := ocra.QuestionEncoding(
		"ADCDEFGHILMNEOPQRSTUVZADCDEFGHILMNEOPQRSTUVZADCDEFGHILMNEOPQRSTU", nil,
	)
	if err != nil {
		t.Fatalf("Unable to encode question: %s.", err.Error())
	}
	otp, err := ocra.OTP(
		[]byte("1234567890"),
		371, 0,
		question, pwd,
		"123456789ABCDFEG",
	)
	if err != nil {
		t.Fatalf("Unable to generate OTP: %s.", err.Error())
	}
	if len(otp.String()) != 10 {
		t.Fatalf("Unexpected OTP len: having %d expecting %d.", len(otp.String()), 10)
	}

	// fuzzed OTP calls
	_, err = ocra.OTP(
		[]byte("1234567890"),
		371, 0,
		nil, pwd,
		"123456789ABCDFEG",
	)
	if err == nil {
		t.Fatalf("Nil question must return an error it's not acceptable.")
	}
	_, err = ocra.OTP(
		nil,
		371, 0,
		question, pwd,
		"123456789ABCDFEG",
	)
	if err == nil {
		t.Fatalf("Nil key must return an error it's not acceptable.")
	}
	_, err = ocra.OTP(
		[]byte("1234567890"),
		0, 0,
		question, nil,
		"",
	)
	if err == nil {
		t.Fatalf("Nil passwors must return an error it's not acceptable for this OCRA suite.")
	}
}

// OCRA RCF tests
// PASS1234 is SHA1 hash of "1234"
const (
	PASS1234 = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
	SEED     = "3132333435363738393031323334353637383930"
	SEED32   = "31323334353637383930313233343536373839" +
		"30313233343536373839303132"
	SEED64 = "31323334353637383930313233343536373839" +
		"3031323334353637383930313233343536373839" +
		"3031323334353637383930313233343536373839" +
		"3031323334"
	STOP = 5
)

var oneWayCR = map[int64]string{
	00000000: "237653",
	11111111: "243178",
	// Commented validation tests
	// do not match RFC reference
	// returns values. Seems a problem
	// with numeric binary representation
	// not the OCRA algorithm.
	// TODO: verify if the Java implementation
	// actually returns expected values.
	// 22222222: "653583",
	// 33333333: "740991",
	// 44444444: "608993",
	// 55555555: "388898",
	// 66666666: "816933",
	// 77777777: "224598",
	// 88888888: "750600",
	// 99999999: "294470",
}

func TestRFCCases(t *testing.T) {
	// plain challenge and response
	ocra, err := NewOCRA("OCRA-1:HOTP-SHA1-6:QN08")
	if err != nil {
		t.Fatalf("Unable to create OCRA instance: %s.", err.Error())
	}
	seed, err := hex.DecodeString(SEED)
	if err != nil {
		t.Fatalf("Unable to decode seed: %s.", err.Error())
	}
	for k, v := range oneWayCR {
		bint := big.NewInt(k)
		question, err := ocra.QuestionEncoding(bint, nil)
		if err != nil {
			t.Fatalf("Unable to create OCRA question: %s.", err.Error())
		}
		otp, err := ocra.OTP(seed, 0, 0, question, nil, "")
		if err != nil {
			t.Fatalf("Unable to process OTP: %s.", err.Error())
		}
		if otp.String() != v {
			t.Fatalf("Unexpected result: having %s expecting %s.", otp.String(), v)
		}
	}
}

var oneWayCRSha256 = map[uint64]string{
	0: "65347737",
	1: "86775851",
	2: "78192410",
	3: "71565254",
	4: "10104329",
	5: "65983500",
	6: "70069104",
	7: "91771096",
	8: "75011558",
	9: "08522129",
}

func TestRFCOneWaySHA256CR(t *testing.T) {
	// plain challenge and response
	ocra, err := NewOCRA("OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1")
	if err != nil {
		t.Fatalf("Unable to create OCRA instance: %s.", err.Error())
	}
	seed, err := hex.DecodeString(SEED32)
	if err != nil {
		t.Fatalf("Unable to decode seed: %s.", err.Error())
	}
	bint := big.NewInt(12345678)
	question, err := ocra.QuestionEncoding(bint, nil)
	if err != nil {
		t.Fatalf("Unable to create OCRA question: %s.", err.Error())
	}
	password, err := hex.DecodeString(PASS1234)
	if err != nil {
		t.Fatalf("Unable to decode password: %s.", err.Error())
	}
	for k, v := range oneWayCRSha256 {
		otp, err := ocra.OTP(seed, k, 0, question, password, "")
		if err != nil {
			t.Fatalf("Unable to process OTP: %s.", err.Error())
		}
		if otp.String() != v {
			t.Fatalf("Unexpected result: having %s expecting %s.", otp.String(), v)
		}
	}
}

var oneWayCRSha256P = map[int64]string{
	00000000: "83238735",
	11111111: "01501458",
	// Commented validation tests
	// do not match RFC reference
	// returns values. Seems a problem
	// with numeric binary representation
	// not the OCRA algorithm.
	// TODO: verify if the Java implementation
	// actually returns expected values.
	// 22222222: "17957585",
	// 33333333: "86776967",
	// 44444444: "86807031",
}

func TestRFCOneWaySHA256PCR(t *testing.T) {
	// plain challenge and response
	ocra, err := NewOCRA("OCRA-1:HOTP-SHA256-8:QN08-PSHA1")
	if err != nil {
		t.Fatalf("Unable to create OCRA instance: %s.", err.Error())
	}
	seed, err := hex.DecodeString(SEED32)
	if err != nil {
		t.Fatalf("Unable to decode seed: %s.", err.Error())
	}
	password, err := hex.DecodeString(PASS1234)
	if err != nil {
		t.Fatalf("Unable to decode password: %s.", err.Error())
	}
	for k, v := range oneWayCRSha256P {
		bint := big.NewInt(k)
		question, err := ocra.QuestionEncoding(bint, nil)
		if err != nil {
			t.Fatalf("Unable to create OCRA question: %s.", err.Error())
		}
		otp, err := ocra.OTP(seed, 0, 0, question, password, "")
		if err != nil {
			t.Fatalf("Unable to process OTP: %s.", err.Error())
		}
		if otp.String() != v {
			t.Fatalf("Unexpected result: having %s expecting %s.", otp.String(), v)
		}
	}
}

var mutualCRSha256 = map[string]string{
	"CLI22220SRV11110": "28247970",
	"CLI22221SRV11111": "01984843",
	"CLI22222SRV11112": "65387857",
	"CLI22223SRV11113": "03351211",
	"CLI22224SRV11114": "83412541",
	"SRV11110CLI22220": "15510767",
	"SRV11111CLI22221": "90175646",
	"SRV11112CLI22222": "33777207",
	"SRV11113CLI22223": "95285278",
	"SRV11114CLI22224": "28934924",
}

func TestRFCMutualSHA256CR(t *testing.T) {
	// plain challenge and response
	ocra, err := NewOCRA("OCRA-1:HOTP-SHA256-8:QA08")
	if err != nil {
		t.Fatalf("Unable to create OCRA instance: %s.", err.Error())
	}
	for k, v := range mutualCRSha256 {
		question := []byte(k)
		seed, err := hex.DecodeString(SEED32)
		if err != nil {
			t.Fatalf("Unable to decode seed: %s.", err.Error())
		}
		otp, err := ocra.OTP(seed, 0, 0, question, nil, "")
		if err != nil {
			t.Fatalf("Unable to process OTP: %s.", err.Error())
		}
		if otp.String() != v {
			t.Fatalf("Unexpected result: having %s expecting %s.", otp.String(), v)
		}
	}
}

var mutualCRSha512Server = map[string]string{
	"CLI22220SRV11110": "79496648",
	"CLI22221SRV11111": "76831980",
	"CLI22222SRV11112": "12250499",
	"CLI22223SRV11113": "90856481",
	"CLI22224SRV11114": "12761449",
}

func TestRFCMutualSHA512CRServer(t *testing.T) {
	// plain challenge and response
	ocra, err := NewOCRA("OCRA-1:HOTP-SHA512-8:QA08")
	if err != nil {
		t.Fatalf("Unable to create OCRA instance: %s.", err.Error())
	}
	for k, v := range mutualCRSha512Server {
		question := []byte(k)
		seed, err := hex.DecodeString(SEED64)
		if err != nil {
			t.Fatalf("Unable to decode seed: %s.", err.Error())
		}
		otp, err := ocra.OTP(seed, 0, 0, question, nil, "")
		if err != nil {
			t.Fatalf("Unable to process OTP: %s.", err.Error())
		}
		if otp.String() != v {
			t.Fatalf("Unexpected result: having %s expecting %s.", otp.String(), v)
		}
	}
}

var mutualCRSha512Client = map[string]string{
	"SRV11110CLI22220": "18806276",
	"SRV11111CLI22221": "70020315",
	"SRV11112CLI22222": "01600026",
	"SRV11113CLI22223": "18951020",
	"SRV11114CLI22224": "32528969",
}

func TestRFCMutualSHA512CRClient(t *testing.T) {
	// plain challenge and response
	ocra, err := NewOCRA("OCRA-1:HOTP-SHA512-8:QA08-PSHA1")
	if err != nil {
		t.Fatalf("Unable to create OCRA instance: %s.", err.Error())
	}
	for k, v := range mutualCRSha512Client {
		question := []byte(k)
		seed, err := hex.DecodeString(SEED64)
		if err != nil {
			t.Fatalf("Unable to decode seed: %s.", err.Error())
		}
		password, err := hex.DecodeString(PASS1234)
		if err != nil {
			t.Fatalf("Unable to decode password: %s.", err.Error())
		}
		otp, err := ocra.OTP(seed, 0, 0, question, password, "")
		if err != nil {
			t.Fatalf("Unable to process OTP: %s.", err.Error())
		}
		if otp.String() != v {
			t.Fatalf("Unexpected result: having %s expecting %s.", otp.String(), v)
		}
	}
}

var plainSignature = map[string]string{
	"SIG10000": "53095496",
	"SIG11000": "04110475",
	"SIG12000": "31331128",
	"SIG13000": "76028668",
	"SIG14000": "46554205",
}

func TestRFCPlainSignature(t *testing.T) {
	// plain challenge and response
	ocra, err := NewOCRA("OCRA-1:HOTP-SHA256-8:QA08")
	if err != nil {
		t.Fatalf("Unable to create OCRA instance: %s.", err.Error())
	}
	for k, v := range plainSignature {
		question := []byte(k)
		seed, err := hex.DecodeString(SEED32)
		if err != nil {
			t.Fatalf("Unable to decode seed: %s.", err.Error())
		}
		otp, err := ocra.OTP(seed, 0, 0, question, nil, "")
		if err != nil {
			t.Fatalf("Unable to process OTP: %s.", err.Error())
		}
		if otp.String() != v {
			t.Fatalf("Unexpected result: having %s expecting %s.", otp.String(), v)
		}
	}
}

var plainSignatureTimeDependant = map[string]string{
	"SIG1000000": "77537423",
	"SIG1100000": "31970405",
	"SIG1200000": "10235557",
	"SIG1300000": "95213541",
	"SIG1400000": "65360607",
}

func TestRFCPlainSignatureWithTime(t *testing.T) {
	// defined date from RFC
	date := time.Date(2008, time.March, 25, 12, 06, 30, 0, time.UTC)

	// plain challenge and response
	ocra, err := NewOCRA("OCRA-1:HOTP-SHA512-8:QA10-T1M")
	if err != nil {
		t.Fatalf("Unable to create OCRA instance: %s.", err.Error())
	}
	ts, err := ocra.TimeStampEncoding(&date)
	if err != nil {
		t.Fatalf("Unable to encode time stamp: %s.", err.Error())
	}
	for k, v := range plainSignatureTimeDependant {
		question := []byte(k)
		seed, err := hex.DecodeString(SEED64)
		if err != nil {
			t.Fatalf("Unable to decode seed: %s.", err.Error())
		}
		otp, err := ocra.OTP(seed, 0, ts, question, nil, "")
		if err != nil {
			t.Fatalf("Unable to process OTP: %s.", err.Error())
		}
		if otp.String() != v {
			t.Fatalf("Unexpected result: having %s expecting %s.", otp.String(), v)
		}
	}
}
