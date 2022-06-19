package example

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"testing"
)

// Test_createPrivateKey 作为 bitcoin 的私钥就是 256bits 的字符串（32B）
//
// 只需要从可信任的随机源读取就可
func Test_createPrivateKey(t *testing.T) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatalf("generate ecdsa private key error %v\n", err)
	}
	t.Logf("private key = %X\n", privateKey)
}

// privateKeyHex 来自 Master BitCoin Generate Private Key
const privateKeyHex = "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD"

var private []byte

func init() {
	var err error
	private, err = hex.DecodeString(privateKeyHex)
	if err != nil {
		panic(err)
	}
}

// Test_createPrivateKey 根据私钥生成公钥
func Test_createPublicKey(t *testing.T) {
	privateKey, publicKey := btcec.PrivKeyFromBytes(private)

	t.Logf("private key = %X\n", privateKey.Serialize())
	t.Logf("public  key = %X\n\n", publicKey.SerializeUncompressed())

	t.Logf("public  key (x) = %X\n", publicKey.X().Bytes())
	t.Logf("public  key (y) = %X\n", publicKey.Y().Bytes())

	t.Logf("public compress key = %X\n", publicKey.SerializeCompressed())
}
