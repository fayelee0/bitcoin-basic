package example

import (
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"testing"
)

func Test_createSeed(t *testing.T) {
	entropy, _ := bip39.NewEntropy(256)
	t.Logf("entropy = %X\n", entropy)

	mnemonic, _ := bip39.NewMnemonic(entropy)
	t.Logf("mnemonic = %s\n", mnemonic)

	seed := bip39.NewSeed(mnemonic, "1234567890")
	t.Logf("seed = %X\n", seed)

	masterKey, _ := bip32.NewMasterKey(seed)
	t.Logf("master = %X\n", masterKey)
}
