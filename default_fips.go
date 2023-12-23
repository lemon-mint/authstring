//go:build boringcrypto || fips
// +build boringcrypto fips

package authstring

import "github.com/lemon-mint/authstring/internal/algs"

const _DEFAULT_ALGORITHM = algs.PBKDF2_V1
