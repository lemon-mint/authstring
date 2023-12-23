package pbkdf2v1

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"

	"github.com/lemon-mint/authstring/internal/algs"
	"github.com/lemon-mint/authstring/internal/randpool"
	"golang.org/x/crypto/pbkdf2"
)

const Algorithm = algs.PBKDF2_V1

type PBKDF2_v1 struct{}

func (a PBKDF2_v1) Algorithm() algs.AlgID { return Algorithm }
func (a PBKDF2_v1) Version() uint16       { return 1 }
func (a PBKDF2_v1) Name() string          { return "PBKDF2_v1" }

// Algorithm: PBKDF2_v1
// Date: 2023-12-23T08:02:32Z
// Hash Size: 32
// Salt Size: 16
// Iterations: 600000
// Hashing Algorithm: SHA256

const (
	_hash       = 32
	_salt       = 16
	_iterations = 600000
	_algorithm  = "SHA256"

	_output = 2 + _hash + _salt
)

func (a PBKDF2_v1) Hash(password []byte) []byte {
	var output [_output]byte

	osalt := output[2 : 2+_salt]
	ohash := output[2+_salt : 2+_salt+_hash]

	binary.LittleEndian.PutUint16(output[0:2], uint16(Algorithm))
	randpool.CSPRNG_RAND(osalt)

	// PreHash
	prehash := sha256.Sum256(password)
	// PBKDF2(password, salt, iterations, hash, hash_algorithm)
	bhash := pbkdf2.Key(prehash[:], osalt, _iterations, _hash, sha256.New)
	for i := range prehash {
		prehash[i] = 0
	}

	copy(ohash, bhash)
	for i := range bhash {
		bhash[i] = 0
	}

	return output[:]
}

func (a PBKDF2_v1) Verify(hash []byte, password []byte) bool {
	if len(hash) < _output {
		return false
	}

	if binary.LittleEndian.Uint16(hash[0:2]) != uint16(Algorithm) {
		return false
	}

	osalt := hash[2 : 2+_salt]
	ohash := hash[2+_salt : 2+_salt+_hash]

	// PreHash
	prehash := sha256.Sum256(password)
	// PBKDF2(password, salt, iterations, hash, hash_algorithm)
	bhash := pbkdf2.Key(prehash[:], osalt, _iterations, _hash, sha256.New)
	for i := range prehash {
		prehash[i] = 0
	}

	if bhash == nil {
		return false
	}

	if subtle.ConstantTimeCompare(ohash, bhash) == 1 {
		return true
	}

	return false
}

var _ algs.Algorithm = (*PBKDF2_v1)(nil)

var Inst PBKDF2_v1
