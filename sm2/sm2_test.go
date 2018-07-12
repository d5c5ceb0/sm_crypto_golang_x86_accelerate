/*
 * Package sm2 implements the Chinese SM2 Algorithm,
 * according to "go/src/crypto/ecdsa".
 * author: weizhang <d5c5ceb0@gmail.com>
 * 2017.02.26
 */

package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"reflect"
	"testing"

	"github.com/d5c5ceb0/sm_crypto_golang/sm3"
)

func testKeyGeneration(t *testing.T, c elliptic.Curve, tag string) {
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Errorf("%s: error: %s", tag, err)
		return
	}
	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("%s: public key invalid: %s", tag, err)
	}
}

func TestKeyGeneration(t *testing.T) {
	c := P256_sm2()
	testKeyGeneration(t, c.Params(), "sm2 p256")

	if testing.Short() {
		return
	}
}

func testSignAndVerify(t *testing.T, c elliptic.Curve, tag string) {
	priv, _ := GenerateKey(c, rand.Reader)

	msg := []byte("testing")
	dig := sm3.Sum(msg)
	hashed := dig[:]
	r, s, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	if !Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("%s: Verify failed", tag)
	}

	msg[0] ^= 0xff
	dig = sm3.Sum(msg)
	hashed = dig[:]
	if Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("%s: Verify always works!", tag)
	}
}

func testVerify(t *testing.T) {
	c := P256_sm2()
	d, _ := new(big.Int).SetString("D84DC07A8426395E0CE43AEA82DB9ACCF2568D0F2D63772D9897D1334D1F20C3", 16)
	priv := new(PrivateKey)
	r := new(big.Int)
	s := new(big.Int)
	priv.PublicKey.Curve = c
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = p256.ScalarBaseMult(d.Bytes())
	//publickey CD459EA427E560E014F420F502055A20471AAE6B97CD5B66F01D87BAB250138B41DA65A7C7058F965EF911D6F5E45B536626DDE93E687C085EB506DC94BEDF79

	hashed := []byte{0x7C, 0x84, 0x31, 0x6F, 0xC7, 0x19, 0x43, 0x1C, 0xA7, 0x92, 0x1A, 0xCE, 0xD9, 0x55, 0xB4, 0x07, 0x60, 0x0C, 0x88, 0x0F, 0x97, 0xD2, 0x18, 0x26, 0xF4, 0x38, 0x35, 0x80, 0x51, 0xD0, 0xCB, 0x21}
	r, _ = new(big.Int).SetString("53572E8EE06A2DC311ED8A6087E6A0E71C8C42E360B10B55983397964F44ECFF", 16)
	s, _ = new(big.Int).SetString("3538D6F877B83AB3C9E298BBA7459C9629B533281A5A823EAC601DE8CFF5A0CB", 16)

	if !Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("%s: const Verify failed")
	}

}
func TestSignAndVerify(t *testing.T) {
	testVerify(t)
	c := P256_sm2()
	testSignAndVerify(t, c.Params(), "sm2 p256")
	if testing.Short() {
		return
	}

	for i := 0; i < 1; i++ {
		testSignAndVerify(t, c.Params(), "sm2 p256")
	}
}

func BenchmarkSignSM2P256(b *testing.B) {
	b.ResetTimer()
	c := P256_sm2()
	hashed := []byte("0123456789abcdef0123456789abcdef")
	priv, _ := GenerateKey(c.Params(), rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Sign(rand.Reader, priv, hashed)
	}
}

func BenchmarkVerifyP256(b *testing.B) {
	b.ResetTimer()
	c := P256_sm2()
	hashed := []byte("0123456789abcdef0123456789abcdef")
	priv, _ := GenerateKey(c.Params(), rand.Reader)
	r, s, _ := Sign(rand.Reader, priv, hashed)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(&priv.PublicKey, hashed, r, s)
	}
}

func TestEncAndDec(t *testing.T) {
	c := P256_sm2()
	prv, _ := GenerateKey(c.Params(), rand.Reader)
	ct, _ := prv.Encrypt(rand.Reader, &prv.PublicKey, []byte{0x00})
	m, _ := prv.Decrypt(ct)
	if reflect.DeepEqual(m, []byte{0x00}) != true {
		t.Errorf("sm2 enc error!")
		return
	}

	for j := 0; j < 1; j++ {
		for i := 1; i < 10; i++ {
			msg := make([]byte, i)
			_, _ = io.ReadFull(rand.Reader, msg[:])
			ct, _ := prv.Encrypt(rand.Reader, &prv.PublicKey, msg)
			mt, err := prv.Decrypt(ct)
			if err != nil {
				t.Errorf("sm2 enc error!")
			}
			if reflect.DeepEqual(mt, msg) != true {
				t.Errorf("sm2 enc error!")
			}
		}
	}
	return
}

func BenchmarkEncSM2P256(b *testing.B) {
	b.ResetTimer()
	c := P256_sm2()
	hashed := []byte("0123456789abcdef0123456789abcdef")
	priv, _ := GenerateKey(c.Params(), rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = priv.Encrypt(rand.Reader, &priv.PublicKey, hashed)
	}
}

func BenchmarkDecP256(b *testing.B) {
	b.ResetTimer()
	c := P256_sm2()
	hashed := []byte("0123456789abcdef0123456789abcdef")
	priv, _ := GenerateKey(c.Params(), rand.Reader)
	ct, _ := priv.Encrypt(rand.Reader, &priv.PublicKey, hashed)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = priv.Decrypt(ct)
	}
}

var testcase_KDF = map[string]string{
	"B8": "ede42e70dcc68b522a79a4b47157c0eeff77a92df1e4416ba288ebc5f71a8851ce1424508a2e0840195fc0342696765c09225c077308a1e670ca403ffa8cc1a160be0a0fdfb9f9c2a620bc5cf0260608cdfb94823a888acc23166e3e77e363122dc40676734d14a010093d9d1769c43ae5355d057c85526e67f8235747d592ed1a1678e137ac1a920e900b2d85e6d45789317258d2af12fd14d751679c4abd91d6a292d11195ab0d06b05faf03f8a9ddbf7557c542afcc49e88a115ed9dbda348bc3f1ebd59940cf15d319fc604ba9aa4077e19a5f0ed4563776018718570466c9e21438d588300bc1d43a619709509cd2501976085460c6f02e3faf0837adae",
	"1AF8DBA88AA8D19CF1960F12960A0D54":                                                                                                 "7e50ea2b18ae40acc1067c09d634fad54016b09b9aea3ed07c34016b459f2b0b33bfcf9be0c18c66f91a169ac390adaa825358f15dd833f92fd8539e830bd88fc1d7c175db85727a7be92471929c3cd25a16945989945a4b7ea1eb353f73216e23aff65d71c2d92fe49fd1e718bc6bd5a99fde4306bfa5773ec67e9a29cbdc4762013e178d38b2883130efec561821e36eb178b82645f4e7bafe9e1fec8b44a5c9a4db9087b3361f7bcb74214f3dcf2ccdaa0880ba7dd13fccc61007b32124569ad08f7adf60a432993cb131c4edc5d65a8d6dc3db916117103999738814459f08b20de5814f17cfddd1d4400952989f14fdb335777a88b25553d66e3831f362",
	"23C596FA83D17C96B50252C421D5BAD604086549BD9D8A5BFD469FC838DC5D535532503F874D73B30B26F9D2F142477A9404907D2E1083E31FE0CBB6D6DBF0A3": "e22fb6de6deb671baefe6d1b7c846174bd486d1bcb0e9ce6fc3abf1eb62f8371566dca973c9e14be4f64e1449cbcd3117c61f2f7b0ae34858ecf0918be88d1231bd2c8a77c4bbc0413ec856fd9149609fa414587ad26f641cf33db2a838431a8726c8fbb5dfcb533ba75c80647ed8ff5a59dc29322020b2180db156667b1422cd462216f8fba01c264a33ba3b875272438f5968069d2c013518f208b9062e350208658aaf164dcd83fa41adcb30f10787eb70044e62f4e0ee10c03afbfcec9af85ba5d37bc5ceb5cfdd3078f2c89a3a0be7c70d988d47a2c0a384c833ee140e4fe1256c36b981829c079099dc14e992e653de0eabc357e1b0a3c9d4bf3201aac",
}

func TestSm3Kdf(t *testing.T) {
	hash := sm3.New()
	out1, _ := sm2KDF(hash, []byte{01}, 0)
	if len(out1) != 0 {
		t.Error("sm3 kdf error!")
	}

	for k, v := range testcase_KDF {
		in, _ := hex.DecodeString(k)
		res, _ := hex.DecodeString(v)
		out, _ := sm2KDF(hash, in, 256)

		if reflect.DeepEqual(res, out) != true {
			t.Error("sm3 kdf error2!")
		}
	}
}
