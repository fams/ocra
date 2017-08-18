//
// packager ocra package
// Author: Guido Ronchetti <guido.ronchetti@nexo.cloud>
// v1.0 16/08/2017
//

package ocra

import (
	"fmt"
)

// OTP manage the single one
// time password data.
type OTP struct {
	size  uint64 // algorithm defined size for OTP;
	Value int32  // actual OTP value.
}

// String returns a zero padded string starting from
// the returned OTP int32 value.
func (t *OTP) String() string {
	f := fmt.Sprintf("%%0%dd", t.size)
	return fmt.Sprintf(f, t.Value)
}
