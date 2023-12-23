package algs

type AlgID uint16

const (
	RESERVED AlgID = iota

	PBKDF2_V1
	ARGON2ID_V1

	_USER_DEFINED AlgID = 32767
)

const FIPS_MIN = PBKDF2_V1
const MODERN_MIN = ARGON2ID_V1

type Algorithm interface {
	Algorithm() AlgID
	Version() uint16
	Name() string
	Hash(password []byte) []byte
	Verify(hash []byte, password []byte) bool
}
