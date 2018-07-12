package sm2

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/d5c5ceb0/sm_crypto_golang/sm3"
)

var (
	ErrKeyDataTooLong = fmt.Errorf("sm2: can't supply requested key data")
	ErrInvalidCurve   = fmt.Errorf("sm2: invalid elliptic curve")
	ErrInvalidMessage = fmt.Errorf("sm2: invalid message")
	ErrTIsZero        = fmt.Errorf("sm2: t is zero")
	ErrC3NoEqual      = fmt.Errorf("sm2: c3` is not equal to c3")
)

var (
	big2To32   = new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
	big2To32M1 = new(big.Int).Sub(big2To32, big.NewInt(1))
)

func incCounter(ctr []byte) {
	if ctr[3]++; ctr[3] != 0 {
		return
	} else if ctr[2]++; ctr[2] != 0 {
		return
	} else if ctr[1]++; ctr[1] != 0 {
		return
	} else if ctr[0]++; ctr[0] != 0 {
		return
	}
	return
}

func sm2KDF(hash hash.Hash, z []byte, kLen int) (k []byte, err error) {
	reps := (kLen + hash.Size() - 1) / hash.Size()
	if big.NewInt(int64(reps)).Cmp(big2To32M1) > 0 {
		return nil, ErrKeyDataTooLong
	}

	counter := []byte{0, 0, 0, 1}
	k = make([]byte, 0)

	for i := 0; i <= reps; i++ {
		hash.Write(z)
		hash.Write(counter)
		k = append(k, hash.Sum(nil)...)
		hash.Reset()
		incCounter(counter)
	}

	k = k[:kLen]
	return
}

func (prv *PrivateKey) Encrypt(rand io.Reader, pub *PublicKey, msg []byte) (ct []byte, err error) {
	kLen := (prv.PublicKey.Curve.Params().BitSize + 7) / 8

	for {
		k, err := randFieldElement(prv.PublicKey.Curve, rand)
		if err != nil {
			return nil, err
		}

		x1, y1 := p256.ScalarBaseMult(k.Bytes())
		x2, y2 := p256.ScalarMult(pub.X, pub.Y, k.Bytes())
		//x1, y1 := prv.Curve.ScalarBaseMult(k.Bytes())
		//x2, y2 := prv.Curve.ScalarMult(pub.X, pub.Y, k.Bytes())

		z := make([]byte, kLen*2)
		x2B := make([]byte, kLen)
		y2B := make([]byte, kLen)
		copy(z[kLen-len(x2.Bytes()):], x2.Bytes())
		copy(z[kLen-len(y2.Bytes()):], y2.Bytes())
		copy(z[:kLen], x2B)
		copy(z[kLen:], y2B)

		hash := sm3.New()
		t, err := sm2KDF(hash, z, len(msg))
		if err != nil {
			return nil, err
		}

		bigT := new(big.Int).SetBytes(t)
		if eq := bigT.Cmp(big.NewInt(0)); eq == 0 {
			continue
		}

		bigT.Xor(bigT, new(big.Int).SetBytes(msg))
		c2 := make([]byte, len(msg))
		copy(c2[len(msg)-len(bigT.Bytes()):], bigT.Bytes())

		hash.Write(x2B)
		hash.Write(msg)
		hash.Write(y2B)
		c3 := hash.Sum(nil)

		c1 := elliptic.Marshal(pub.Curve, x1, y1)
		ct = make([]byte, len(c1)+len(msg)+len(c3))
		copy(ct, c1)
		copy(ct[len(c1):], c3)
		copy(ct[len(c1)+len(msg)+len(c3)-len(c2):], c2)
		break
	}

	return
}
func (prv *PrivateKey) Decrypt(c []byte) (m []byte, err error) {
	kLen := (prv.PublicKey.Curve.Params().BitSize + 7) / 8
	hash := sm3.New()
	hLen := hash.Size()

	R := new(PublicKey)
	R.Curve = prv.PublicKey.Curve
	R.X, R.Y = elliptic.Unmarshal(R.Curve, c[:kLen*2+1])
	/*
		if !R.Curve.IsOnCurve(R.X, R.Y) {
			err = ErrInvalidCurve
			return
		}
	*/

	x2, y2 := p256.ScalarMult(R.X, R.Y, prv.D.Bytes())
	//x2, y2 := prv.Curve.ScalarMult(R.X, R.Y, prv.D.Bytes())

	z := make([]byte, kLen*2)
	x2B := make([]byte, kLen)
	y2B := make([]byte, kLen)
	copy(z[kLen-len(x2.Bytes()):], x2.Bytes())
	copy(z[kLen-len(y2.Bytes()):], y2.Bytes())
	copy(z[:kLen], x2B)
	copy(z[kLen:], y2B)

	t, err := sm2KDF(hash, z, len(c)-(kLen*2+1)-hLen)
	if err != nil {
		return
	}

	bigT := new(big.Int).SetBytes(t)
	if eq := bigT.Cmp(big.NewInt(0)); eq == 0 {
		return nil, ErrTIsZero
	}

	cBig := new(big.Int).SetBytes(c[kLen*2+1+hLen:])

	bigT.Xor(bigT, cBig)
	m1 := make([]byte, len(c)-(kLen*2+1)-hLen)
	copy(m1[len(c)-(kLen*2+1)-hLen-len(bigT.Bytes()):], bigT.Bytes())

	hash.Write(x2B)
	hash.Write(m1)
	hash.Write(y2B)
	c3 := hash.Sum(nil)

	c3t := c[kLen*2+1 : kLen*2+1+hLen]
	if ok := bytes.Equal(c3, c3t); !ok {
		return nil, ErrC3NoEqual
	}

	return m1, nil
}
