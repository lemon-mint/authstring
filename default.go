//go:build !boringcrypto && !fips
// +build !boringcrypto,!fips

package authstring

import "github.com/lemon-mint/authstring/internal/algs"

const _DEFAULT_ALGORITHM = algs.ARGON2ID_V1
