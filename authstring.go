package authstring

import (
	"encoding/base64"
	"encoding/binary"

	"github.com/lemon-mint/authstring/internal/algs"
	"github.com/lemon-mint/authstring/internal/argon2idv1"
	"github.com/lemon-mint/authstring/internal/pbkdf2v1"
)

func AuthStringWithAlgorithm(password []byte, algorithm uint16) string {
	switch algs.AlgID(algorithm) {
	case algs.PBKDF2_V1:
		return base64.RawURLEncoding.EncodeToString(pbkdf2v1.Inst.Hash(password))
	case algs.ARGON2ID_V1:
		return base64.RawURLEncoding.EncodeToString(argon2idv1.Inst.Hash(password))
	}
	panic("Unsupported algorithm")
}

func AuthString(password []byte) string {
	return base64.RawURLEncoding.EncodeToString(_Inst.Hash(password))
}

func VerifyAuthString(password []byte, hash string) (ok bool, needUpgrade bool) {
	h, err := base64.RawURLEncoding.DecodeString(hash)
	if err != nil {
		return false, false
	}
	if len(h) < 2 {
		return false, false
	}

	halg := algs.AlgID(binary.LittleEndian.Uint16(h[0:2]))
	if halg == _DEFAULT_ALGORITHM {
		return _Inst.Verify(h, password), false
	}

	switch halg {
	case algs.PBKDF2_V1:
		return pbkdf2v1.Inst.Verify(h, password), false
	case algs.ARGON2ID_V1:
		return argon2idv1.Inst.Verify(h, password), false
	}

	return false, true
}
