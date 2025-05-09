package main

import (
	"fmt"
	he "github.com/SamBridgess/homomorphicEncryption"
	"github.com/SamBridgess/homomorphicEncryption/bfvMath"
	"github.com/SamBridgess/homomorphicEncryption/ckksMath"
	_ "github.com/lib/pq"
	"log"
	"reflect"
	"runtime"
	"strings"
)

const (
	host           = "localhost"
	port           = 5432
	userClient     = "client"
	passwordClient = "123456"
	dbname         = "encrypted_db"

	serverUrl = "https://127.0.0.1:443"
)

func main() {
	retrievedEncryptedDataCkks, retrievedEncryptedDataBfv := clientSelect()

	ckksParams, err := he.GetCKKSParamsFromServer(serverUrl + "/get_ckks_params")
	bfvParams, err := he.GetBFVParamsFromServer(serverUrl + "/get_bfv_params")

	ckksEvalKeys, err := he.GetCkksEvalKeysFromServer(serverUrl + "/get_ckks_eval_keys")
	bfvEvalKeys, err := he.GetBfvEvalKeysFromServer(serverUrl + "/get_bfv_eval_keys")

	he.SetupClient(ckksParams, bfvParams, ckksEvalKeys.EvalKey1, bfvEvalKeys.EvalKey1)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("CKKS Demonstration:")
	performConstOperationCkks(ckksMath.AddConst, retrievedEncryptedDataCkks[0], 2.0)
	performConstOperationCkks(ckksMath.MultByConst, retrievedEncryptedDataCkks[0], 2.0)
	performConstOperationCkks(ckksMath.SubtractConst, retrievedEncryptedDataCkks[0], 2.0)
	performConstOperationCkks(ckksMath.MultByConst, retrievedEncryptedDataCkks[0], 2.0)
	performConstOperationCkks(ckksMath.DivByConst, retrievedEncryptedDataCkks[0], 2.0)
	performOperation2Ckks(ckksMath.Sum, retrievedEncryptedDataCkks[0], retrievedEncryptedDataCkks[1])
	performOperation2Ckks(ckksMath.Subtract, retrievedEncryptedDataCkks[0], retrievedEncryptedDataCkks[1])
	performOperation2Ckks(ckksMath.Mult, retrievedEncryptedDataCkks[0], retrievedEncryptedDataCkks[1])
	performOperation1Ckks(ckksMath.Pow2, retrievedEncryptedDataCkks[0])
	performArrayOperationCkks(ckksMath.ArraySum, retrievedEncryptedDataCkks)
	performArrayOperationCkks(ckksMath.ArrayMean, retrievedEncryptedDataCkks)
	performArrayOperationWithParamReturningArrayCkks(ckksMath.MovingAverage, retrievedEncryptedDataCkks, 3)
	performArrayOperationCkks(ckksMath.Variance, retrievedEncryptedDataCkks)
	performArrayOperation2Ckks(ckksMath.Covariance, retrievedEncryptedDataCkks, retrievedEncryptedDataCkks)
	performOperation3Ckks(ckksMath.ArithmeticProgressionElementN, retrievedEncryptedDataCkks[4], retrievedEncryptedDataCkks[3], retrievedEncryptedDataCkks[0])
	performOperation3Ckks(ckksMath.ArithmeticProgressionSum, retrievedEncryptedDataCkks[4], retrievedEncryptedDataCkks[3], retrievedEncryptedDataCkks[0])

	fmt.Println("\nBFV Demonstration:")
	performConstOperationBfv(bfvMath.MultByPositiveConst, retrievedEncryptedDataBfv[0], uint64(2))
	performOperation2Bfv(bfvMath.Sum, retrievedEncryptedDataBfv[0], retrievedEncryptedDataBfv[1])
	performOperation2Bfv(bfvMath.Subtract, retrievedEncryptedDataBfv[0], retrievedEncryptedDataBfv[1])
	performOperation2Bfv(bfvMath.Mult, retrievedEncryptedDataBfv[0], retrievedEncryptedDataBfv[1])
	performArrayOperationBfv(bfvMath.ArraySum, retrievedEncryptedDataBfv)
}

func performConstOperationCkks(operation ckksMath.ConstOperation, data []byte, constant float64) {
	calcRes, err := operation(data, constant)
	if err != nil {
		log.Fatal(err)
	}
	decryptedCalcResultCkks, err := he.SendComputationResultToServerCkks(serverUrl+"/decrypt_computations_ckks", calcRes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("CKKS %s result: %f \n", getFunctionName(operation), decryptedCalcResultCkks)
}
func performOperation1Ckks(operation ckksMath.Operation1, data []byte) {
	calcRes, err := operation(data)
	if err != nil {
		log.Fatal(err)
	}
	decryptedCalcResultCkks, err := he.SendComputationResultToServerCkks(serverUrl+"/decrypt_computations_ckks", calcRes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("CKKS %s result: %f \n", getFunctionName(operation), decryptedCalcResultCkks)
}
func performOperation2Ckks(operation ckksMath.Operation2, data []byte, data2 []byte) {
	calcRes, err := operation(data, data2)
	if err != nil {
		log.Fatal(err)
	}
	decryptedCalcResultCkks, err := he.SendComputationResultToServerCkks(serverUrl+"/decrypt_computations_ckks", calcRes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("CKKS %s result: %f \n", getFunctionName(operation), decryptedCalcResultCkks)
}
func performArrayOperationCkks(operation ckksMath.ArrayOperation, data [][]byte) {
	calcRes, err := operation(data)
	if err != nil {
		log.Fatal(err)
	}
	decryptedCalcResultCkks, err := he.SendComputationResultToServerCkks(serverUrl+"/decrypt_computations_ckks", calcRes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("CKKS %s result: %f \n", getFunctionName(operation), decryptedCalcResultCkks)
}
func performArrayOperation2Ckks(operation ckksMath.ArrayOperation2, data [][]byte, data2 [][]byte) {
	calcRes, err := operation(data, data2)
	if err != nil {
		log.Fatal(err)
	}
	decryptedCalcResultCkks, err := he.SendComputationResultToServerCkks(serverUrl+"/decrypt_computations_ckks", calcRes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("CKKS %s result: %f \n", getFunctionName(operation), decryptedCalcResultCkks)
}
func performOperation3Ckks(operation ckksMath.Operation3, data []byte, data2 []byte, data3 []byte) {
	calcRes, err := operation(data, data2, data3)
	if err != nil {
		log.Fatal(err)
	}
	decryptedCalcResultCkks, err := he.SendComputationResultToServerCkks(serverUrl+"/decrypt_computations_ckks", calcRes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("CKKS %s result: %f \n", getFunctionName(operation), decryptedCalcResultCkks)
}
func performArrayOperationWithParamReturningArrayCkks(operation ckksMath.ArrayOperationWithParamReturningArray, data [][]byte, param int) {
	calcRes, err := operation(data, param)
	if err != nil {
		log.Fatal(err)
	}

	var decryptedArray = make([]float64, len(calcRes))
	for i, val := range calcRes {
		decryptedCalcResultCkks, err := he.SendComputationResultToServerCkks(serverUrl+"/decrypt_computations_ckks", val)
		if err != nil {
			log.Fatal(err)
		}
		decryptedArray[i] = decryptedCalcResultCkks
	}

	fmt.Printf("CKKS %s result: %.2f \n", getFunctionName(operation), decryptedArray)
}

func performConstOperationBfv(operation bfvMath.ConstOperation, data []byte, constant uint64) {
	calcRes, err := operation(data, constant)
	if err != nil {
		log.Fatal(err)
	}
	decryptedCalcResultCkks, err := he.SendComputationResultToServerBfv(serverUrl+"/decrypt_computations_bfv", calcRes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BFV %s result: %d \n", getFunctionName(operation), decryptedCalcResultCkks)
}
func performOperation2Bfv(operation bfvMath.Operation2, data []byte, data2 []byte) {
	calcRes, err := operation(data, data2)
	if err != nil {
		log.Fatal(err)
	}
	decryptedCalcResultCkks, err := he.SendComputationResultToServerBfv(serverUrl+"/decrypt_computations_bfv", calcRes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BFV %s result: %d \n", getFunctionName(operation), decryptedCalcResultCkks)
}
func performArrayOperationBfv(operation bfvMath.ArrayOperation, data [][]byte) {
	calcRes, err := operation(data)
	if err != nil {
		log.Fatal(err)
	}
	decryptedCalcResultCkks, err := he.SendComputationResultToServerBfv(serverUrl+"/decrypt_computations_bfv", calcRes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BFV %s result: %d \n", getFunctionName(operation), decryptedCalcResultCkks)
}

func getFunctionName(f interface{}) string {
	ptr := reflect.ValueOf(f).Pointer()
	funcName := runtime.FuncForPC(ptr).Name()
	parts := strings.Split(funcName, ".")
	return parts[len(parts)-1]
}

func clientSelect() ([][]byte, [][]byte) {
	psqlInfo := he.NewDBConnectionInfo(host, port, userClient, passwordClient, dbname)
	db, err := he.OpenConnection(psqlInfo)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var retrievedEncryptedDataCkks = make([][]byte, 5)
	var retrievedEncryptedDataBfv = make([][]byte, 5)

	err = db.QueryRow("SELECT encryptedDataCkks1, encryptedDataCkks2, encryptedDataCkks3, encryptedDataCkks4, encryptedDataCkks5, encryptedDataBfv1, encryptedDataBfv2, encryptedDataBfv3, encryptedDataBfv4, encryptedDataBfv5 FROM encrypted_data_ckks_bfv WHERE id = (SELECT MAX(id) FROM encrypted_data_ckks_bfv)").Scan(
		&retrievedEncryptedDataCkks[0],
		&retrievedEncryptedDataCkks[1],
		&retrievedEncryptedDataCkks[2],
		&retrievedEncryptedDataCkks[3],
		&retrievedEncryptedDataCkks[4],
		&retrievedEncryptedDataBfv[0],
		&retrievedEncryptedDataBfv[1],
		&retrievedEncryptedDataBfv[2],
		&retrievedEncryptedDataBfv[3],
		&retrievedEncryptedDataBfv[4])
	if err != nil {
		log.Fatal(err)
	}
	return retrievedEncryptedDataCkks, retrievedEncryptedDataBfv
}
