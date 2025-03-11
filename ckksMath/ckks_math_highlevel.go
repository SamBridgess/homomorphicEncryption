package ckksMath

import (
	"errors"
)

type ArrayOperation func([][]byte) ([]byte, error)
type ArrayOperation2 func([][]byte, [][]byte) ([]byte, error)
type Operation3 func([]byte, []byte, []byte) ([]byte, error)

// ArraySum Returns the encrypted sum of all elements of passed array in []byte
func ArraySum(encryptedDataArray [][]byte) ([]byte, error) {
	if len(encryptedDataArray) == 0 {
		return nil, errors.New("cannot use empty array")
	}

	sumCiphertext, err := makeZeroCiphertext(encryptedDataArray[0])
	if err != nil {
		return nil, err
	}

	for _, encryptedData := range encryptedDataArray {
		ciphertext, err := unmarshallIntoNewCiphertext(encryptedData)
		if err != nil {
			return nil, err
		}

		CkksEvaluator.Add(sumCiphertext, ciphertext, sumCiphertext)
	}

	return sumCiphertext.MarshalBinary()
}

// ArrayMean Calculates the encrypted mean of all elements of passed array in []byte
func ArrayMean(encryptedDataArray [][]byte) ([]byte, error) {
	sum, err := ArraySum(encryptedDataArray)
	if err != nil {
		return nil, err
	}

	ciphertext, err := unmarshallIntoNewCiphertext(sum)
	if err != nil {
		return nil, err
	}

	return CkksEvaluator.MultByConstNew(ciphertext, 1.0/float64(len(encryptedDataArray))).MarshalBinary()
}

// MovingAverage Returns an array, containing len(encryptedDataArray) - windowSize elements,
// each representing a calculated mean of numbers within a shifting window of size windowSize
func MovingAverage(encryptedDataArray [][]byte, windowSize int) ([][]byte, error) {
	movingArrayLen := len(encryptedDataArray) - windowSize
	r := make([][]byte, movingArrayLen)
	for i := 0; i < movingArrayLen; i++ {
		var err error
		r[i], err = ArrayMean(encryptedDataArray[i : i+windowSize])
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Variance Calculates variance of a passed array in []bytes
func Variance(encryptedDataArray [][]byte) ([]byte, error) { //дисперсия
	if len(encryptedDataArray) == 0 {
		return nil, errors.New("cannot use empty array")
	}

	mean, err := ArrayMean(encryptedDataArray)
	if err != nil {
		return nil, err
	}

	ciphertextSum, err := makeZeroCiphertext(encryptedDataArray[0])
	if err != nil {
		return nil, err
	}

	for _, encryptedData := range encryptedDataArray {
		sub, err := Subtract(encryptedData, mean)
		if err != nil {
			return nil, err
		}

		pow, err := Pow2(sub)
		if err != nil {
			return nil, err
		}

		ciphertextPow, err := unmarshallIntoNewCiphertext(pow)
		if err != nil {
			return nil, err
		}

		CkksEvaluator.Relinearize(ciphertextPow, ciphertextPow)

		CkksEvaluator.Add(ciphertextSum, ciphertextPow, ciphertextSum)
	}

	sumSquaredDiff, err := ciphertextSum.MarshalBinary()
	result, err := DivByConst(sumSquaredDiff, float64(len(encryptedDataArray)))
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Covariance Calculates covariance coefficient between two encrypted arrays in []byte
func Covariance(encryptedDataArray1 [][]byte, encryptedDataArray2 [][]byte) ([]byte, error) {
	if len(encryptedDataArray1) != len(encryptedDataArray2) {
		return nil, errors.New("arrays must be of the same length")
	}
	if len(encryptedDataArray1) == 0 || len(encryptedDataArray2) == 0 {
		return nil, errors.New("cannot use empty array")
	}

	mean1, err := ArrayMean(encryptedDataArray1)
	if err != nil {
		return nil, err
	}

	mean2, err := ArrayMean(encryptedDataArray2)
	if err != nil {
		return nil, err
	}

	ciphertextSum, err := makeZeroCiphertext(encryptedDataArray1[0])
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(encryptedDataArray1); i++ {
		sub1, err := Subtract(encryptedDataArray1[i], mean1)
		if err != nil {
			return nil, err
		}

		sub2, err := Subtract(encryptedDataArray2[i], mean2)
		if err != nil {
			return nil, err
		}

		mult, err := Mult(sub1, sub2)
		if err != nil {
			return nil, err
		}

		ciphertextMult, err := unmarshallIntoNewCiphertext(mult)
		if err != nil {
			return nil, err
		}

		CkksEvaluator.Relinearize(ciphertextMult, ciphertextMult)

		CkksEvaluator.Add(ciphertextSum, ciphertextMult, ciphertextSum)
	}

	sum, err := ciphertextSum.MarshalBinary()
	result, err := DivByConst(sum, float64(len(encryptedDataArray1)))
	if err != nil {
		return nil, err
	}

	return result, nil
}

// ArithmeticProgressionElementN Calculates the N element of arithmetic progression in []byte.
// Requires the first element of progression and the difference between two members of progression
func ArithmeticProgressionElementN(firstMember []byte, dif []byte, n []byte) ([]byte, error) {
	dec, err := SubtractConst(n, 1)
	if err != nil {
		return nil, err
	}

	mult, err := Mult(dif, dec)
	if err != nil {
		return nil, err
	}

	return Sum(firstMember, mult)
}

// ArithmeticProgressionSum Calculates sum of arithmetic progression in []byte.
// Requires the first element of progression, the difference between two members of progression
// and number of elements in progression
func ArithmeticProgressionSum(firstMember []byte, dif []byte, numberOfMembers []byte) ([]byte, error) {
	elementN, err := ArithmeticProgressionElementN(firstMember, dif, numberOfMembers)
	if err != nil {
		return nil, err
	}

	sum, err := Sum(firstMember, elementN)
	if err != nil {
		return nil, err
	}

	sumCiphertext, err := unmarshallIntoNewCiphertext(sum)
	if err != nil {
		return nil, err
	}
	CkksEvaluator.Relinearize(sumCiphertext, sumCiphertext)

	sum, err = sumCiphertext.MarshalBinary()
	if err != nil {
		return nil, err
	}

	mult, err := Mult(numberOfMembers, sum)
	if err != nil {
		return nil, err
	}

	return DivByConst(mult, 2.0)
}
