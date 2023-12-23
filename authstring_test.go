package authstring

import (
	"testing"

	"github.com/lemon-mint/authstring/internal/argon2idv1"
	"github.com/lemon-mint/authstring/internal/pbkdf2v1"
)

var _HashedPasswords = []string{
	"AgD3k90iAMn6YMNs-W4E3S9ZNAcZaY251p_98sWGIyNOdgDAunYjQcZ-1evpszHlwrU",
	"AgDepvFsi9fICSxz2EeTHy1ZTewH97TMlxvgfKBDDcHVxqTr2nG0pQS2OqB2_h2Hm_M",
	"AgDt_OlNl2bEujBRmF4QgCV1fe7aqHCujLvCU2BwqfErsZAw55si-jD8nh-SbPkeYo4",
	"AgC1m1Slf8biUnCxSxOPLzGhafRLpprcLyDuStJNozyYtGXi0bufPoj4UWKJG9lGgRM",
	"AgBG8-R8iIkoHdAztAIOqTeGlWi9Bbg9IQZwQFPhCa_6ZxQf4Bcimy6qbKGc-pj_X_0",
	"AgDa7VU83dY9NEShR3ZQa0hpo_7E41pyaKYsVg6qugDNLVkkukLeQf4Lgzch5xtHuv4",
	"AgAJ5K39jisr4H6aOBXR2v-LW9bMfp4z-GSw-DGxhoKenPN7npoTDrrfckmgEmJuFew",
	"AgCU7JvIePkRBkxswcR3hgMZBeTxH9-CaPwztsb3dZ_znlVtaN0CwW3imu7CwDHSACM",
	"AQBHTXH5DOELGUeUQ7TbTkln2TnBcucmORju5jU14S5UPe-z5PDItHpAenLzd3u8wSk",
	"AQDnvnrWdlQxdik7mv-HDAwVyKTgM_--3fIx8lPBDpgPVAilYJNizB2Bw61mLeAebPU",
	"AQB80La-wDAkNCOA64Lq5YihwUlbA_5l4hM54mtoyShplUJcOe7Frn_6Junpvkg0sok",
	"AQDzBKFgR2JfXvyj0-BZXGtwwLPaJZD_2UxIib66Bmc8lR0dVuxlZ3NExJSQxNyv-Ng",
}

var password = []byte("password")

func TestHashAlgorithm(t *testing.T) {
	hash0 := pbkdf2v1.Inst.Hash(password)
	if !pbkdf2v1.Inst.Verify(hash0, password) {
		t.Fatal("pbkdf2v1 failed")
	}
	hash1 := argon2idv1.Inst.Hash(password)
	if !argon2idv1.Inst.Verify(hash1, password) {
		t.Fatal("argon2idv1 failed")
	}
}

func TestHashPasswordWithAlgorithm(t *testing.T) {
	for _, alg := range []uint16{
		ALG_PBKDF2_V1,
		ALG_ARGON2ID_V1,
	} {
		hash := AuthStringWithAlgorithm(password, alg)
		if ok, needUpgrade := VerifyAuthString(password, hash); !ok || needUpgrade {
			t.Errorf("Verify(Alg:%d) returned ok:%v, needUpgrade:%v", alg, ok, needUpgrade)
		}
	}
}

func TestHashPassword(t *testing.T) {
	hash := AuthString(password)
	if ok, needUpgrade := VerifyAuthString(password, hash); !ok || needUpgrade {
		if !ok {
			t.Error("VerifyPassword failed")
		}
		if needUpgrade {
			t.Error("Expected needUpgrade to be false")
		}
	}
}

func TestVerifyPassword(t *testing.T) {
	for _, hash := range _HashedPasswords {
		if ok, needUpgrade := VerifyAuthString(password, hash); !ok || needUpgrade {
			if !ok {
				t.Error("Expected VerifyPassword to succeed, got ok:", ok, "needUpgrade:", needUpgrade)
			}
			if needUpgrade {
				t.Error("Expected needUpgrade to be false")
			}
		}
	}

	ok, needUpgrade := VerifyAuthString(password, "AAAAAAAA")
	if ok || !needUpgrade {
		t.Error("Expected VerifyPassword to fail, got ok:", ok, "needUpgrade:", needUpgrade)
	}

	for _, hash := range _HashedPasswords {
		ok, needUpgrade = VerifyAuthString([]byte("fuzzword"), hash)
		if ok || needUpgrade {
			t.Error("Expected VerifyPassword to fail, got ok:", ok, "needUpgrade:", needUpgrade)
		}
	}

	ok, needUpgrade = VerifyAuthString([]byte("fuzzword"), "&&&&&")
	if ok || needUpgrade {
		t.Error("Expected VerifyPassword to fail, got ok:", ok, "needUpgrade:", needUpgrade)
	}

	ok, needUpgrade = VerifyAuthString(password, "&&&&&")
	if ok || needUpgrade {
		t.Error("Expected VerifyPassword to fail, got ok:", ok, "needUpgrade:", needUpgrade)
	}

	ok, needUpgrade = VerifyAuthString(password, "AgAJ5K39jisr4H6FOBXR2v-LW9bMfp4z-GSw-DGxhoKenPN7npoTDrrfckmgEmJuFew")
	if ok || needUpgrade {
		t.Error("Expected VerifyPassword to fail, got ok:", ok, "needUpgrade:", needUpgrade)
	}

	ok, needUpgrade = VerifyAuthString(password, "AQDDDD")
	if ok || needUpgrade {
		t.Error("Expected VerifyPassword to fail, got ok:", ok, "needUpgrade:", needUpgrade)
	}

	ok, needUpgrade = VerifyAuthString(password, "A")
	if ok || needUpgrade {
		t.Error("Expected VerifyPassword to fail, got ok:", ok, "needUpgrade:", needUpgrade)
	}

	ok, needUpgrade = VerifyAuthString(password, "AA")
	if ok || needUpgrade {
		t.Error("Expected VerifyPassword to fail, got ok:", ok, "needUpgrade:", needUpgrade)
	}

	ok, needUpgrade = VerifyAuthString(password, "AQA")
	if ok || needUpgrade {
		t.Error("Expected VerifyPassword to fail, got ok:", ok, "needUpgrade:", needUpgrade)
	}
}
