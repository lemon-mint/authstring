package argon2idv1

import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/lemon-mint/authstring/internal/algs"
	"github.com/lemon-mint/authstring/internal/randpool"
	"golang.org/x/crypto/argon2"
)

const Algorithm = algs.ARGON2ID_V1

type Argon2ID_v1 struct{}

func (a Argon2ID_v1) Algorithm() algs.AlgID { return Algorithm }
func (a Argon2ID_v1) Version() uint16       { return 1 }
func (a Argon2ID_v1) Name() string          { return "Argon2ID_v1" }

// Algorithm: Argon2ID_v1
// Date: 2023-12-23T08:02:32Z
// Hash Size: 32
// Salt Size: 16
// Iterations: 2
// Parallelism: 1
// Memory: 20480 KiB

const (
	_hash        = 32
	_salt        = 16
	_iterations  = 2
	_memory      = 20480 // 2MiB
	_parallelism = 1

	_output = 2 + _hash + _salt
)

func (a Argon2ID_v1) Hash(password []byte) []byte {
	var output [_output]byte

	osalt := output[2 : 2+_salt]
	ohash := output[2+_salt : 2+_salt+_hash]

	binary.LittleEndian.PutUint16(output[0:2], uint16(Algorithm))
	randpool.CSPRNG_RAND(osalt)
	bhash := argon2.IDKey(password, output[2:2+_salt], _iterations, _memory, _parallelism, _hash)
	copy(ohash, bhash)

	return output[:]
}

func (a Argon2ID_v1) Verify(hash []byte, password []byte) bool {
	if len(hash) < _output {
		return false
	}

	if binary.LittleEndian.Uint16(hash[0:2]) != uint16(Algorithm) {
		return false
	}

	osalt := hash[2 : 2+_salt]
	ohash := hash[2+_salt : 2+_salt+_hash]

	bhash := argon2.IDKey(password, osalt, _iterations, _memory, _parallelism, _hash)
	if bhash == nil {
		return false
	}

	if subtle.ConstantTimeCompare(ohash, bhash) == 1 {
		return true
	}

	return false
}

var _ algs.Algorithm = (*Argon2ID_v1)(nil)

var Inst Argon2ID_v1
