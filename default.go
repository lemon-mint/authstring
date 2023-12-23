//go:build !boringcrypto && !fips
// +build !boringcrypto,!fips

package authstring

import (
	"github.com/lemon-mint/authstring/internal/algs"
	"github.com/lemon-mint/authstring/internal/argon2idv1"
)

const _DEFAULT_ALGORITHM = algs.ARGON2ID_V1
const _MIN_ALGORITHM = algs.MODERN_MIN

var _Inst = &argon2idv1.Inst
