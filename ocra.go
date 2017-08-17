//
// packager ocra package
// Author: Guido Ronchetti <guido.ronchetti@nexo.cloud>
// v1.0 16/08/2017
//

package ocra

import (
	"crypto/hmac"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const powers10 = []int{
	1,
	10,
	100,
	1000,
	10000,
	100000,
	1000000,
	10000000,
	100000000,
	1000000000,
	1000000000,
}

type ocraMode int

const (
	cHOTPSHA1   ocraMode = iota
	cHOTPSHA256 ocraMode = iota
	cHOTPSHA512 ocraMode = iota
)

type ocraCrypto struct {
	mode       ocraMode // hashing supported modes;
	truncation uint     // 4-10 digits.
}

type ocraQuestionFormat int

const (
	cQuestionAlphanumeric ocraQuestionFormat = iota
	cQuestionNumeric      ocraQuestionFormat = iota
	cQuestionHexadecimal  ocraQuestionFormat = iota
)

type ocraTimeStampFormat int

const (
	cTimeStampSeconds ocraTimeStampFormat = iota
	cTimeStampMinutes ocraTimeStampFormat = iota
	cTimeStampHours   ocraTimeStampFormat = iota
)

type ocraPasswordHashFunction int

const (
	cSHA1   ocraPasswordHashFunction = iota
	cSHA256 ocraPasswordHashFunction = iota
	cSHA512 ocraPasswordHashFunction = iota
)

type ocraDataIn struct {
	// mandatory
	questionFormat ocraQuestionFormat
	questionSize   uint
	// optional time stamp
	timeStamp    bool
	timeStepSize uint
	timeStepUnit ocraTimeStampFormat
	// optional counter
	counter bool
	// optional session
	session     bool
	sessionSize uint
	// optional password
	password bool
	hashMode ocraPasswordHashFunction
}

// OCRA represent the basic tructure used to execute
// challenge and response ops.
type OCRA struct {
	algorithm      uint        // version of the OCRA algorithm;
	cryptoFunction *ocraCrypto // crypto mode;
	dataIn         *ocraDataIn // Data input.
}

const (
	cOcraSuiteRegex = `^(OCRA-[0-9]):(HOTP-[A-Z0-9]{4,}-[0-9]):((C-)?Q[ANH]{1,1}[0-9]{1,2}(-P[A-Z0-9]{4,6})?(-S[0-9]{3,3})?(-T[0-9]{1,2}[SMH])?)$`
)

var suiteRegex *regexp.Regexp = nil

func init() {
	if suiteRegex == nil {
		suiteRegex = regexp.MustCompile(cOcraSuiteRegex)
	}
}

func algorithmVersion(algorithm string) uint {
	s := strings.TrimPrefix(algorithm, "OCRA-")
	value, _ := strconv.ParseUint(s, 10, 32)
	return value
}

func cryptoFunction(cryptoFunc string) (*ocraCrypto, error) {
	components := strings.Split(cryptoFunc, "-")
	if len(components) != 3 {
		return nil, fmt.Errorf(
			"unexpected number of crypto function componrents: having %d expecting 3",
			len(components),
		)
	}

	result := &ocraCrypto{}
	// hashing function used in HMAC
	switch components[1] {
	case "SHA256":
		result.mode = cHOTPSHA256
	case "SHA512":
		result.mode = cHOTPSHA512
	case "SHA1":
	default:
		result.mode = cHOTPSHA1
	}
	// truncation value
	value, err := strconv.ParseUint(components[2], 10, 32)
	if err != nil {
		return nil, err
	}
	if (value > 0 &&
		value < 4) ||
		value > 10 {
		return nil, fmt.Errorf(
			"unexpected truncation value must be 0 or between 4 and 10, having %d",
			value,
		)
	}
	result.truncation = value

	return result, nil
}

func dataInput(dataIn string) *ocraDataIn {
	// set default for mandatory elemets
	result := &ocraDataIn{
		questionFormat: cQuestionNumeric,
		questionSize:   8,
		timeStepUnit:   cTimeStampMinutes,
		timeStepSize:   1,
		sessionSize:    64,
		hashMode:       cSHA1,
	}
	// [C] | QFxx | [PH | Snnn | TG]
	for value, idx := range strings.Split(dataIn, "-") {
		switch value[0] {
		case "C":
			result.counter = true
		case "Q":
			s := strings.TrimPrefix(value, "Q")
			if len(s) != 3 {
				continue
			}
			size, err := strconv.ParseUint(s[1:], 10, 32)
			if err != nil {
				continue
			}
			result.questionSize = size
			switch s[0] {
			case "A":
				result.questionFormat = cQuestionAlphanumeric
			case "N":
				result.questionFormat = cQuestionNumeric
			case "H":
				result.questionFormat = cQuestionHexadecimal
			}
		case "S":
			result.session = true
			s := strings.TrimPrefix(value, "S")
			size, err := strconv.ParseUint(s[1:], 10, 32)
			if err != nil {
				continue
			}
			result.sessionSize = size
		case "T":
			result.timeStamp = true
			s := strings.TrimPrefix(value, "T")
			lapse, err := strconv.ParseUint(s[:len(s)-1], 10, 32)
			if err != nil {
				continue
			}
			result.timeStepSize = lapse
			switch s[len(s)-1] {
			case "S":
				result.timeStepUnit = cTimeStampSeconds
			case "H":
				result.timeStepUnit = cTimeStampHours
			}
		case "P":
			result.password = true
			s := strings.TrimPrefix(value, "P")
			switch s {
			case "SHA256":
				result.hashMode = cSHA256
			case "SHA512":
				result.hashMode = cSHA512
			}
		}
	}
	return result
}

// NewOCRA generate an OCRA struct from the available options that can
// be descrived in a RFC6287 standard OCRASuite.
// An OCRASuite value is a text string that captures one mode of
// operation for OCRA, completely specifying the various options for
// that computation.  An OCRASuite value is represented as follows:
// <Algorithm>:<CryptoFunction>:<DataInput>
func NewOCRA(suite string) (*OCRA, error) {
	if suiteRegex == nil ||
		suiteRegex.MatchString(suite) != true {
		return nil, fmt.Errorf(
			"invalid suite format, should match the following format: %s",
			cOcraSuiteRegex,
		)
	}

	// decompose suite string
	components := strings.Split(suite, ":")
	if len(components) != 3 {
		return nil, fmt.Errorf(
			"invalid suite format, should have 3, \":\" separated components but found %d",
			len(components),
		)
	}

	// get values
	version := algorithmVersion(components[0])
	if version != 1 {
		return nil, fmt.Errorf(
			"unknown OCRA version, this implementation refers to RFC6287 that describes version 1 of the algorithm",
		)
	}
	cryptoFunc, err := cryptoFunction(components[1])
	if err != nil {
		return nil, err
	}

	return &OCRA{
		algorithm:      version,
		cryptoFunction: cryptoFunc,
		dataIn:         dataInput(components[2]),
	}, nil
}

// generateOTP implements RFC6287 to produce an OTP starting from a
// challenge shared with the server.
//
// This structure is the concatenation over byte array of the OCRASuite
// value as defined in section 6 with the different parameters used in
// the computation, save for the secret key K.
//
// DataInput = {OCRASuite | 00 | C | Q | P | S | T} where:
// 	* OCRASuite is a value representing the suite of operations to
// 	  compute an OCRA response
// 	* 00 is a byte value used as a separator
//  * C is an unsigned 8-byte counter value processed high-order bit
//    first, and MUST be synchronized between all parties; It loops
//    around from "{Hex}0" to "{Hex}FFFFFFFFFFFFFFFF" and then starts
//    over at "{Hex}0".  Note that 'C' is optional for all OCRA modes
//    described in this document.
// 	* Q, mandatory, is a 128-byte list of (concatenated) challenge
//    question(s) generated by the parties; if Q is less than 128 bytes,
//    then it should be padded with zeroes to the right.
// 	* P is a hash (SHA-1 [RFC3174], SHA-256 and SHA-512 [SHA2] are
//    supported) value of PIN/password that is known to all parties
//    during the execution of the algorithm; the length of P will depend
//    on the hash function that is used.
// 	* S is a UTF-8 [RFC3629] encoded string of length up to 512 bytes
//    that contains information about the current session; the length of
//    S is defined in the OCRASuite string.
// 	* T is an 8-byte unsigned integer in big-endian order (i.e., network
//    byte order) representing the number of time-steps (seconds,
//    minutes, hours, or days depending on the specified granularity)
//    since midnight UTC of January 1, 1970 [UT].  More specifically, if
//    the OCRA computation includes a timestamp T, you should first
//    convert your current local time to UTC time; you can then derive
//    the UTC time in the proper format (i.e., seconds, minutes, hours,
//    or days elapsed from epoch time); the size of the time-step is
//    specified in the OCRASuite string as described in Section 6.3.
//
// When computing a response, the concatenation order is always the
// following:
//
// C | OTHER-PARTY-GENERATED-CHALLENGE-QUESTION |
// YOUR-GENERATED-CHALLENGE-QUESTION | P| S | T
//
// If a value is empty (i.e., a certain input is not used in the
// computation) then the value is simply not represented in the string.
// The counter on the token or client MUST be incremented every time a
// new computation is requested by the user.  The server's counter value
// MUST only be incremented after a successful OCRA authentication.
// If a value is empty (i.e., a certain input is not used in the
// computation) then the value is simply not represented in the string.
// The counter on the token or client MUST be incremented every time a
// new computation is requested by the user.  The server's counter value
// MUST only be incremented after a successful OCRA authentication.
func (o *OCRA) OTP(
	counter uint64,
	challenge [128]byte,
	password []byte,
	session string,
	timeStamp uint64,
) (string, error) {
	return "", nil
}
