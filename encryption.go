package homomorphic_encryption_lib

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ckks"
	"reflect"
)

var methodMap = map[string]map[string]reflect.Value{}

func init() {
	registerPackage("ckks", ckks.NewParameters)
	registerPackage("bfv", bfv.NewParameters)
}

// Функция регистрации всех методов из пакета
func registerPackage(name string, instance interface{}) {
	// Получаем объект через reflect
	typ := reflect.TypeOf(instance)
	value := reflect.ValueOf(instance)

	// Создаем вложенную мапу для методов пакета
	methodMap[name] = make(map[string]reflect.Value)

	for i := 0; i < typ.NumMethod(); i++ {
		method := typ.Method(i)
		methodMap[name][method.Name] = value.MethodByName(method.Name)
		fmt.Printf("Registered method: %s.%s\n", name, method.Name)
	}
}

func reflectionCall(algo string) {

}

func EncryptHom(data float64, algo string) ([]byte, error) {

	encoder := ckks.NewEncoder(CkksParams)
	encryptor := ckks.NewEncryptor(CkksParams, Keys.Pk)

	plaintext := ckks.NewPlaintext(CkksParams, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	encoder.Encode([]float64{data}, plaintext, CkksParams.LogSlots())

	ciphertext := encryptor.EncryptNew(plaintext)
	return ciphertext.MarshalBinary()
}

func EncryptHom2(data float64) ([]byte, error) {
	encoder := ckks.NewEncoder(CkksParams)
	encryptor := ckks.NewEncryptor(CkksParams, Keys.Pk)

	plaintext := ckks.NewPlaintext(CkksParams, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	encoder.Encode([]float64{data}, plaintext, CkksParams.LogSlots())

	ciphertext := encryptor.EncryptNew(plaintext)
	return ciphertext.MarshalBinary()
}
