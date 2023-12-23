//go:build boringcrypto || fips
// +build boringcrypto fips

package authstring

import (
	"github.com/lemon-mint/authstring/internal/algs"
	"github.com/lemon-mint/authstring/internal/pbkdf2v1"
)

const _DEFAULT_ALGORITHM = algs.PBKDF2_V1
const _MIN_ALGORITHM = algs.FIPS_MIN

var _Inst = &pbkdf2v1.Inst
