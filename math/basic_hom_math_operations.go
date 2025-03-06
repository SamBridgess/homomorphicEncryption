package math

import (
	he "github.com/SamBridgess/homomorphic_encryption_lib"
	"github.com/ldsec/lattigo/v2/ckks"
)

// MakeZeroCiphertext takes any encrypted data and subtracts it from itself
// making a *ckks.Ciphertext containing 0 when decrypted
func MakeZeroCiphertext(someEncryptedData []byte) (*ckks.Ciphertext, error) {
	ciphertext := ckks.NewCiphertext(CkksParams, 1, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(someEncryptedData)
	if err != nil {
		return nil, err
	}
	return Evaluator.SubNew(ciphertext, ciphertext), nil
}

// MakeCiphertextFromFloat takes a float64 number and any encrypted data to make a zeroCiphertext from
// and then adds the float64 to zero which makes an encrypted representation of the initial float64 number
func MakeCiphertextFromFloat(number float64, someEncryptedData []byte) *ckks.Ciphertext {
	zeroCiphertext, _ := MakeZeroCiphertext(someEncryptedData)
	ciphertext := Evaluator.AddConstNew(zeroCiphertext, number)
	return ciphertext
}

// AddConst adds a float64 addValue to encrypted data, producing []byte of encrypted data
// containing a sum of encryptedData data and addValue when decrypted
func AddConst(encryptedData []byte, addValue float64) ([]byte, error) {
	ciphertext := ckks.NewCiphertext(CkksParams, 1, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	return Evaluator.AddConstNew(ciphertext, addValue).MarshalBinary()
}

// MultByConst multiplies encryptedData by float64 multValue, producing []byte of encrypted data
// containing a product of encryptedData and multValue when decrypted
func MultByConst(encryptedData []byte, multValue float64) ([]byte, error) {
	ciphertext := ckks.NewCiphertext(CkksParams, 1, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	return Evaluator.MultByConstNew(ciphertext, multValue).MarshalBinary()
}

// SumOf2 adds encryptedData to encryptedData2, producing []byte of encrypted data
// containing a sum of encryptedData data and encryptedData2 when decrypted
func SumOf2(encryptedData []byte, encryptedData2 []byte) ([]byte, error) {
	ciphertext := ckks.NewCiphertext(CkksParams, 1, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	ciphertext2 := ckks.NewCiphertext(CkksParams, 1, CkksParams.MaxLevel(), CkksParams.DefaultScale())

	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	err = ciphertext2.UnmarshalBinary(encryptedData2)
	if err != nil {
		return nil, err
	}

	return Evaluator.AddNew(ciphertext, ciphertext2).MarshalBinary()
}

// MultOf2 multiplies encryptedData by encryptedData2, producing []byte of encrypted data
// containing a product of encryptedData and encryptedData2 when decrypted
func MultOf2(encryptedData []byte, encryptedData2 []byte) ([]byte, error) {
	ciphertext := ckks.NewCiphertext(CkksParams, 1, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	ciphertext2 := ckks.NewCiphertext(CkksParams, 1, CkksParams.MaxLevel(), CkksParams.DefaultScale())

	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	err = ciphertext2.UnmarshalBinary(encryptedData2)
	if err != nil {
		return nil, err
	}

	return Evaluator.MulNew(ciphertext, ciphertext2).MarshalBinary()
}

// DivByConst divides encryptedDataDividend by float64 encryptedDataDivisor, producing []byte of
// encrypted data containing a quotient of encryptedDataDividend and encryptedDataDivisor
// when decrypted
func DivByConst(encryptedDataDividend []byte, encryptedDataDivisor float64) ([]byte, error) {
	ciphertext := ckks.NewCiphertext(CkksParams, 1, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(encryptedDataDividend)
	if err != nil {
		return nil, err
	}

	return Evaluator.MultByConstNew(ciphertext, 1.0/encryptedDataDivisor).MarshalBinary()
}

func TwoStepDivision(encryptedData []byte, encryptedData2 []byte, url string) ([]byte, error) {
	divisorDecrypted, err := he.SendComputationResultToServer(url, encryptedData2)
	if err != nil {
		return nil, err
	}

	return DivByConst(encryptedData, divisorDecrypted)
}

/*
func Inv(encryptedData []byte, steps int, ckksParams ckks.Parameters) ([]byte, error) {
	evaluator := getNewEvaluator(ckksParams)

	ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	return evaluator.InverseNew(ciphertext, steps).MarshalBinary()
}

func Sqrt(encryptedData []byte, url string, ckksParams ckks.Parameters) ([]byte, error) {
	ciphertext_a := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	err := ciphertext_a.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	ciphertext_x := ciphertext_a
	evaluator := getNewEvaluator(ckksParams)

	for {
		divisorDecrypted, err := homomorphic_encryption_lib.SendComputationResultToServer(url, ciphertext_x.MarshalBinary())
		if err != nil {
			return nil, err
		}

		inv_x := MakeCiphertextFromFloat(1/divisorDecrypted, encryptedData, evaluator, ckksParams)
		//halfCiphertext := MakeCiphertextFromFloat(0.5, encryptedData, evaluator, ckksParams)
		tmp := evaluator.AddNew(ciphertext_x, evaluator.MulNew(ciphertext_a, inv_x))
		nex_X, err := MultByConst(encryptedData, 0.5, ckksParams)
		if err != nil {
			return nil, err
		}
	}
}
*/
