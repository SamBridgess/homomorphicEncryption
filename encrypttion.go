package homomorphic_encryption_lib

import (
	"fmt"
	"reflect"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ckks"
)

type EncryptionMethod int

const (
	CKKS EncryptionMethod = iota
	BFV
)

func callFunction(pkg string, function string, params ...interface{}) []reflect.Value {
	var funcValue reflect.Value
	switch pkg {
	case "ckks":
		funcValue = reflect.ValueOf(ckks.NewEncoder)
	case "bfv":
		funcValue = reflect.ValueOf(bfv.NewEncoder)
	default:
		panic("unsupported package")
	}

	in := make([]reflect.Value, len(params))
	for i, param := range params {
		in[i] = reflect.ValueOf(param)
	}

	return funcValue.Call(in)
}

func Encrypt(method EncryptionMethod, data float64) ([]byte, error) {
	var pkg string
	var params interface{}

	switch method {
	case CKKS:
		pkg = "ckks"
		params = CkksParams
	case BFV:
		pkg = "bfv"
		params = BfvParams
	default:
		return nil, fmt.Errorf("unsupported encryption method")
	}

	encoder := callFunction(pkg, "NewEncoder", params)[0].Interface()

	encodeMethod := reflect.ValueOf(encoder).MethodByName("Encode")
	plaintext := encodeMethod.Call([]reflect.Value{
		reflect.ValueOf([]float64{data}),
		reflect.ValueOf(params),
	})[0].Interface()

	encryptor := callFunction(pkg, "NewEncryptor", params, Keys.Pk)[0].Interface()
	encryptMethod := reflect.ValueOf(encryptor).MethodByName("EncryptNew")
	ciphertext := encryptMethod.Call([]reflect.Value{
		reflect.ValueOf(plaintext),
	})[0].Interface()

	return ciphertext.([]byte), nil
}
