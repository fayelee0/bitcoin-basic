package example

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"testing"
)

// Test_createP2PK 直接创建 key pair
func Test_createP2PK(t *testing.T) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("create private key error %v\n", err)
	}

	t.Logf("private key = %X\n", privateKey.Serialize())
	t.Logf("public  key = %X\n", privateKey.PubKey().SerializeUncompressed())
}

// Test_createP2PKH 创建 key pair base58(ripemd160(sha256(pub key)))
func Test_createP2PKH(t *testing.T) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("create private key error %v\n", err)
	}

	// 1. 公钥地址本质是一个坐标点 (x, y) 通过函数 K = k * G 计算出来
	// 2. 如果知道 x 值，就可以通过函数推导出来
	// 3. 对于 y 值，通过函数推导出来的值有两个 +y, -y
	//
	// 4. 未压缩的公钥 1 + 32 + 32 = 65    0x04 + hex(x) + hex(y)
	// 5.  压缩的公钥  1 + 32 = 33         0x0[2|3][y 的符号位是 0 ~ 0x02 1 ~ 0x03] + hex(x)

	t.Logf("private key = %X\n", privateKey.Serialize())
	t.Logf("public  key = %X\n", privateKey.PubKey().SerializeCompressed())
}
