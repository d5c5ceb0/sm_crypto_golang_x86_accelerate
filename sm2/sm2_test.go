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
	//"fmt"
	"math/big"
	"sm_crypto_golang/sm3"
	"testing"
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
	//	fmt.Printf("D: %x\n", priv.D)
	//	fmt.Printf("X: %x\n", priv.PublicKey.X)
	//fmt.Printf("Y: %x\n", priv.PublicKey.Y)
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
	//fmt.Printf("D: %x\n", priv.D)
	//fmt.Printf("X: %x\n", priv.PublicKey.X)
	//fmt.Printf("Y: %x\n", priv.PublicKey.Y)
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
		//fmt.Println(i)
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
