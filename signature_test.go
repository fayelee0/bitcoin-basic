package example

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

var testData = []byte("hello world!")

// Test_cryptoData 对数据做加密/解密
func Test_cryptoData(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key error %v\n", err)
	}

	publicKey := privateKey.Public()

	// 对数据做加密
	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey.(*rsa.PublicKey), testData)
	if err != nil {
		t.Fatalf("encrypt data error %v\n", err)
	}

	// 对加密数据做解密
	message, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipher)
	if err != nil {
		t.Fatalf("decrypt data error %v\n", err)
	}

	if !bytes.Equal(message, testData) {
		t.Errorf("message not equal")
	}
}

// Test_nonDeterministicSignatureAlgo 非确定性签名算法 ECDSA
func Test_signData(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key error %v\n", err)
	}

	publicKey := privateKey.Public()

	// 对待签名的数据做标准化 HASH
	hashed := sha256.Sum256(testData[:])

	// 对数据做签名
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hashed[:])
	if err != nil {
		t.Fatalf("signature error %v\n", err)
	}
	t.Logf("signature = %X\n", signature)

	// 验证签名
	if !ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), hashed[:], signature) {
		t.Errorf("verify signature failure")
	}
}
