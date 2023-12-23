package algs

type AlgID uint16

const (
	RESERVED AlgID = iota
	ARGON2ID_V1
	PBKDF2_V1

	_USER_DEFINED AlgID = 32767
)

type Algorithm interface {
	Algorithm() AlgID
	Version() uint16
	Name() string
	Hash(password []byte) []byte
	Verify(hash []byte, password []byte) bool
}
