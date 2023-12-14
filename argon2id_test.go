package argon2id

import (
	"regexp"
	"strings"
	"testing"
	"unsafe"
)

func TestCreateHash(t *testing.T) {
	hashRX, err := regexp.Compile(`^\$argon2id\$v=19\$m=65536,t=1,p=[0-9]{1,4}\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	if err != nil {
		t.Fatal(err)
	}

	hash1, err := CreateHash(string2ByteSlice("pa$$word"), DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	if !hashRX.MatchString(hash1) {
		t.Errorf("hash %q not in correct format", hash1)
	}

	hash2, err := CreateHash(string2ByteSlice("pa$$word"), DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Compare(hash1, hash2) == 0 {
		t.Error("hashes must be unique")
	}
}

func TestComparePasswordAndHash(t *testing.T) {
	hash, err := CreateHash(string2ByteSlice("pa$$word"), DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	match, err := ComparePasswordAndHash(string2ByteSlice("pa$$word"), hash)
	if err != nil {
		t.Fatal(err)
	}

	if !match {
		t.Error("expected password and hash to match")
	}

	match, err = ComparePasswordAndHash(string2ByteSlice("otherPa$$word"), hash)
	if err != nil {
		t.Fatal(err)
	}

	if match {
		t.Error("expected password and hash to not match")
	}
}

func TestDecodeHash(t *testing.T) {
	hash, err := CreateHash(string2ByteSlice("pa$$word"), DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	params, _, _, err := DecodeHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	if *params != *DefaultParams {
		t.Fatalf("expected %#v got %#v", *DefaultParams, *params)
	}
}

func TestCheckHash(t *testing.T) {
	hash, err := CreateHash(string2ByteSlice("pa$$word"), DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	ok, params, err := CheckHash(string2ByteSlice("pa$$word"), hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected password to match")
	}
	if *params != *DefaultParams {
		t.Fatalf("expected %#v got %#v", *DefaultParams, *params)
	}
}

func TestStrictDecoding(t *testing.T) {
	// "bug" valid hash: $argon2id$v=19$m=65536,t=1,p=2$UDk0zEuIzbt0x3bwkf8Bgw$ihSfHWUJpTgDvNWiojrgcN4E0pJdUVmqCEdRZesx9tE
	ok, _, err := CheckHash(string2ByteSlice("bug"), "$argon2id$v=19$m=65536,t=1,p=2$UDk0zEuIzbt0x3bwkf8Bgw$ihSfHWUJpTgDvNWiojrgcN4E0pJdUVmqCEdRZesx9tE")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected password to match")
	}

	// changed one last character of the hash
	ok, _, err = CheckHash(string2ByteSlice("bug"), "$argon2id$v=19$m=65536,t=1,p=2$UDk0zEuIzbt0x3bwkf8Bgw$ihSfHWUJpTgDvNWiojrgcN4E0pJdUVmqCEdRZesx9tF")
	if err == nil {
		t.Fatal("Hash validation should fail")
	}

	if ok {
		t.Fatal("Hash validation should fail")
	}
}

func TestVariant(t *testing.T) {
	// Hash contains wrong variant
	_, _, err := CheckHash(string2ByteSlice("pa$$word"), "$argon2i$v=19$m=65536,t=1,p=2$mFe3kxhovyEByvwnUtr0ow$nU9AqnoPfzMOQhCHa9BDrQ+4bSfj69jgtvGu/2McCxU")
	if err != ErrIncompatibleVariant {
		t.Fatalf("expected error %s", ErrIncompatibleVariant)
	}
}

func string2ByteSlice(str string) []byte {
	if str == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(str), len(str))
}
