//
// packager ocra package
// Author: Guido Ronchetti <guido.ronchetti@nexo.cloud>
// v1.0 16/08/2017
//

package ocra

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

var powers10 = []int32{
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
	truncation uint64   // 4-10 digits.
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
	questionSize   uint64
	// optional time stamp
	timeStamp    bool
	timeStepSize uint64
	timeStepUnit ocraTimeStampFormat
	// optional counter
	counter bool
	// optional session
	session     bool
	sessionSize uint64
	// optional password
	password bool
	hashMode ocraPasswordHashFunction
}

// OCRA represent the basic tructure used to execute
// challenge and response ops.
type OCRA struct {
	suite          string      // the textual suite representation;
	algorithm      uint64      // version of the OCRA algorithm;
	cryptoFunction *ocraCrypto // crypto mode;
	dataIn         *ocraDataIn // Data input.
	// concurrency managemnt
	mtx sync.RWMutex // provides concurrency safety for multiple routines access.
}

const (
	cOcraSuiteRegex = `^(OCRA-[0-9]{1,1}):(HOTP-[A-Z0-9]{4,6}-[0-9]{1,2}):((C-)?Q[ANH]{1,1}[0-9]{1,2}(-P[A-Z0-9]{4,6})?(-S[0-9]{3,3})?(-T[0-9]{1,2}[SMH])?)$`
)

var suiteRegex *regexp.Regexp = nil

func init() {
	if suiteRegex == nil {
		suiteRegex = regexp.MustCompile(cOcraSuiteRegex)
	}
}

func algorithmVersion(algorithm string) uint64 {
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
	components := strings.Split(dataIn, "-")
	// [C] | QFxx | [PH | Snnn | TG]
	for _, value := range components {
		switch value[0] {
		case 'C':
			result.counter = true
		case 'Q':
			s := strings.TrimPrefix(value, "Q")
			if len(s) < 2 ||
				len(s) > 3 {
				continue
			}
			size, err := strconv.ParseUint(s[1:], 10, 32)
			if err != nil {
				continue
			}
			if size >= 4 &&
				size <= 64 {
				result.questionSize = size
			}
			switch s[0] {
			case 'A':
				result.questionFormat = cQuestionAlphanumeric
			case 'N':
				result.questionFormat = cQuestionNumeric
			case 'H':
				result.questionFormat = cQuestionHexadecimal
			}
		case 'S':
			result.session = true
			s := strings.TrimPrefix(value, "S")
			size, err := strconv.ParseUint(s, 10, 32)
			if err != nil {
				continue
			}
			result.sessionSize = size
		case 'T':
			result.timeStamp = true
			s := strings.TrimPrefix(value, "T")
			lapse, err := strconv.ParseUint(s[:len(s)-1], 10, 32)
			if err != nil {
				continue
			}
			result.timeStepSize = lapse
			switch s[len(s)-1] {
			case 'S':
				result.timeStepUnit = cTimeStampSeconds
			case 'H':
				result.timeStepUnit = cTimeStampHours
			}
		case 'P':
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
		suite:          suite,
		algorithm:      version,
		cryptoFunction: cryptoFunc,
		dataIn:         dataInput(components[2]),
	}, nil
}

func (o *OCRA) validateAndPadQuestion(question []byte) ([]byte, error) {
	if len(question) < 4 ||
		len(question) > 128 {
		return nil, fmt.Errorf(
			"invalid question size should be >4 and <128 bytes but found %d",
			len(question),
		)
	}
	buf := new(bytes.Buffer)
	size, err := buf.Write(question)
	if err != nil {
		return nil, err
	}
	for ; size < 128; size++ {
		buf.WriteByte(0x0)
	}
	return buf.Bytes(), nil
}

func (o *OCRA) validatePassword(password []byte) ([]byte, error) {
	switch o.dataIn.hashMode {
	case cSHA256:
		if len(password) != sha256.Size {
			return nil, fmt.Errorf(
				"unexpected password hash len: %d != %d should be a SHA256 hash",
				len(password),
				sha256.Size,
			)
		}
	case cSHA512:
		if len(password) != sha512.Size {
			return nil, fmt.Errorf(
				"unexpected password hash len: %d != %d should be a SHA512 hash",
				len(password),
				sha512.Size,
			)
		}
	case cSHA1:
	default:
		if len(password) != sha1.Size {
			return nil, fmt.Errorf(
				"unexpected password hash len: %d != %d should be a SHA1 hash",
				len(password),
				sha1.Size,
			)
		}
	}
	return password, nil
}

func (o *OCRA) validateSession(session string) ([]byte, error) {
	if uint64(len(session)) != o.dataIn.sessionSize {
		return nil, fmt.Errorf(
			"session string len mismatch: suite require %d but found %d",
			o.dataIn.sessionSize,
			len(session),
		)
	}
	buf := new(bytes.Buffer)
	// the following function call (WriteString)
	// never rise an error but sometimes panics,
	// see bytes documentation for details:
	// https://golang.org/pkg/bytes/
	buf.WriteString(session)
	// validate UTF8 nature
	resultingData := buf.Bytes()
	if utf8.Valid(resultingData) != true {
		return nil, fmt.Errorf(
			"produced byte slice contains non UTF8 values",
		)
	}
	return resultingData, nil
}

func (o *OCRA) dataInputConcatenation(
	counter, timeStamp uint64,
	question, password []byte,
	session string,
) ([]byte, error) {
	// DataInput = {OCRASuite | 00 | C | Q | P | S | T}
	buf := new(bytes.Buffer)

	// the following function calls (WriteString,WriteByte)
	// never rise an error but sometimes panics,
	// see bytes documentation for details:
	// https://golang.org/pkg/bytes/

	// add OCRASuite string
	buf.WriteString(o.suite)
	// add 0x0 byte separator
	buf.WriteByte(0x0)
	// add (optionally) counter
	if o.dataIn.counter {
		err := binary.Write(buf, binary.BigEndian, counter)
		if err != nil {
			return nil, err
		}
	}
	// manage questions
	validatedQuestion, err := o.validateAndPadQuestion(question)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(validatedQuestion)
	if err != nil {
		return nil, err
	}
	// add (optionally) password
	if o.dataIn.password {
		validatedPwd, err := o.validatePassword(password)
		if err != nil {
			return nil, err
		}
		_, err = buf.Write(validatedPwd)
		if err != nil {
			return nil, err
		}
	}
	// add (optionally) session
	if o.dataIn.session {
		validatedSession, err := o.validateSession(session)
		if err != nil {
			return nil, err
		}
		_, err = buf.Write(validatedSession)
		if err != nil {
			return nil, err
		}
	}
	// add time stamp
	if o.dataIn.timeStamp {
		err := binary.Write(buf, binary.BigEndian, timeStamp)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
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
	key []byte,
	counter, timeStamp uint64,
	question, password []byte,
	session string,
) (int32, error) {
	if key == nil ||
		len(key) == 0 {
		return 0, fmt.Errorf(
			"invalid key value must be not nil and of len > 0",
		)
	}
	// lock OCRA instance
	o.mtx.RLock()
	defer o.mtx.RUnlock()

	// prepare message
	msg, err := o.dataInputConcatenation(
		counter, timeStamp,
		question, password,
		session,
	)
	if err != nil {
		return 0, err
	}
	// select hashing function
	var hm hash.Hash = nil
	switch o.cryptoFunction.mode {
	case cHOTPSHA256:
		hm = hmac.New(sha256.New, key)
	case cHOTPSHA512:
		hm = hmac.New(sha512.New, key)
	case cHOTPSHA1:
	default:
		hm = hmac.New(sha1.New, key)
	}
	// compute HMAC

	hm.Write(msg)
	hashed := hm.Sum(nil)
	if len(hashed) < sha1.Size {
		return 0, fmt.Errorf(
			"unexpected hashed data len must not > %d",
			sha1.Size,
		)
	}

	// extract selected bytes to get 32 bit integer value
	offset := int32(hashed[len(hashed)-1] & 0x0f)
	numeric := int32(((hashed[offset] & 0x7f) << 24) |
		((hashed[offset+1] & 0xff) << 16) |
		((hashed[offset+2] & 0xff) << 8) |
		(hashed[offset+3] & 0xff))

	fmt.Printf("%v -> %v -> %v\n",
		hashed[offset],
		(hashed[offset])&0x7f,
		(hashed[offset]&0x7f)<<24,
	)

	// truncation value is validated when creating OCRA
	// struct
	decimal := int32(numeric % powers10[o.cryptoFunction.truncation])
	fmt.Printf("%v\n%d %d %d %d\n", hashed, offset, hashed[offset], numeric, decimal)

	return decimal, nil
}

func (o *OCRA) questionValidation(value interface{}) ([]byte, error) {
	switch o.dataIn.questionFormat {
	case cQuestionAlphanumeric:
		alphanum, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf(
				"mismatching question value type: having %s expecting string",
				reflect.TypeOf(value),
			)
		}
		if len(alphanum) != int(o.dataIn.questionSize) {
			return nil, fmt.Errorf(
				"mismatching question value len: having %d expecting %d",
				len(alphanum),
				o.dataIn.questionSize,
			)
		}
		buf := new(bytes.Buffer)
		// the following function call (WriteString)
		// never rise an error but sometimes panics,
		// see bytes documentation for details:
		// https://golang.org/pkg/bytes/
		buf.WriteString(alphanum)
		return buf.Bytes(), nil
	case cQuestionNumeric:
		bigint, ok := value.(big.Int)
		if !ok {
			return nil, fmt.Errorf(
				"mismatching question value type: having %s expecting big int",
				reflect.TypeOf(value),
			)
		}
		// automatically orders in big endian
		representation := bigint.Bytes()
		if len(representation) > int(o.dataIn.questionSize) ||
			len(representation) < 4 {
			return nil, fmt.Errorf(
				"mismatching question value len: having %d expecting >%d and <%d",
				len(representation),
				4,
				o.dataIn.questionSize,
			)
		}
		return representation, nil
	case cQuestionHexadecimal:
		hexed, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf(
				"mismatching question value type: having %s expecting string",
				reflect.TypeOf(value),
			)
		}
		decoded, err := hex.DecodeString(hexed)
		if err != nil {
			return nil, err
		}
		if len(decoded) != int(o.dataIn.questionSize) {
			return nil, fmt.Errorf(
				"mismatching question value len: having %d expecting %d",
				len(decoded),
				o.dataIn.questionSize,
			)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf(
			"unknown question format",
		)
	}
}

func (o *OCRA) QuestionEncoding(
	value interface{},
	otherPartyGenerated interface{},
) ([]byte, error) {
	// lock OCRA instance
	o.mtx.RLock()
	defer o.mtx.RUnlock()

	buf := new(bytes.Buffer)
	if otherPartyGenerated != nil {
		otherValidated, err := o.questionValidation(otherPartyGenerated)
		if err != nil {
			return nil, err
		}
		_, err = buf.Write(otherValidated)
		if err != nil {
			return nil, err
		}
	}
	validated, err := o.questionValidation(value)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(validated)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (o *OCRA) PasswordEncoding(password []byte) ([]byte, error) {
	if password == nil ||
		len(password) == 0 {
		return nil, fmt.Errorf(
			"invalid password should be not nil nor of len zero",
		)
	}
	// lock OCRA instance
	o.mtx.RLock()
	defer o.mtx.RUnlock()

	// hash password
	switch o.dataIn.hashMode {
	case cSHA1:
		hashed := sha1.Sum(password)
		return hashed[:], nil
	case cSHA256:
		hashed := sha256.Sum256(password)
		return hashed[:], nil
	case cSHA512:
		hashed := sha512.Sum512(password)
		return hashed[:], nil
	default:
		return nil, fmt.Errorf(
			"unknown password hash mode",
		)
	}
}
