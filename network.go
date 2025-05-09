package homomorphicEncryption

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ckks"
	"io"
	"net/http"
)

type DecryptedResultResponseInt struct {
	DecryptedResult int64 `json:"decrypted_result"`
}

type DecryptedResultResponseFloat struct {
	DecryptedResult float64 `json:"decrypted_result"`
}

type BfvEvalKeysResult struct {
	EvalKeys string `json:"bfv_eval_keys"`
}

type CkksEvalKeysResult struct {
	EvalKeys string `json:"ckks_eval_keys"`
}

// HttpsServer Basic https server configuration
var (
	HttpsServer = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}
)

// StartSecureServer Start HTTPS server. Port must be passed as is, without ':'
func StartSecureServer(port string, certFile string, keyFile string) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.POST("/decrypt_computations_ckks", handleDecryptCkks)
	r.GET("/get_ckks_params", handleGetCkksParams)
	r.GET("/get_ckks_eval_keys", handleGetEvalKeysCkks)

	r.POST("/decrypt_computations_bfv", handleDecryptBfv)
	r.GET("/get_bfv_params", handleGetBfvParams)
	r.GET("/get_bfv_eval_keys", handleGetEvalKeysBfv)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	err := server.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		panic("HTTPS server could not start: " + err.Error())
	}
}

// GetCKKSParamsFromServer Retrieve CKKS parameters from server
func GetCKKSParamsFromServer(serverURL string) (ckks.Parameters, error) {
	client := HttpsServer

	resp, err := client.Get(serverURL)
	if err != nil {
		return ckks.Parameters{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ckks.Parameters{}, err
	}

	var response struct {
		CKKSParams string `json:"ckks_params"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return ckks.Parameters{}, err
	}

	var ckksParams ckks.Parameters
	if err := json.Unmarshal([]byte(response.CKKSParams), &ckksParams); err != nil {
		return ckks.Parameters{}, err
	}

	return ckksParams, nil
}

// GetBFVParamsFromServer Retrieve BFV parameters from server
func GetBFVParamsFromServer(serverURL string) (bfv.Parameters, error) {
	client := HttpsServer

	resp, err := client.Get(serverURL)
	if err != nil {
		return bfv.Parameters{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return bfv.Parameters{}, err
	}

	var response struct {
		BFVParams string `json:"bfv_params"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return bfv.Parameters{}, err
	}

	var bfvParams bfv.Parameters
	if err := json.Unmarshal([]byte(response.BFVParams), &bfvParams); err != nil {
		return bfv.Parameters{}, err
	}

	return bfvParams, nil
}

// GetCKKSParamsFromServer Retrieve CKKS EvalKeys from server
func GetCkksEvalKeysFromServer(serverURL string) (EvalKeys, error) {
	client := HttpsServer

	resp, err := client.Get(serverURL)
	if err != nil {
		return EvalKeys{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return EvalKeys{}, err
	}

	response := CkksEvalKeysResult{}
	if err := json.Unmarshal(body, &response); err != nil {
		return EvalKeys{}, err
	}

	var ckksEvalKeys EvalKeys
	if err := json.Unmarshal([]byte(response.EvalKeys), &ckksEvalKeys); err != nil {
		return EvalKeys{}, err
	}

	return ckksEvalKeys, nil
}

// GetCKKSParamsFromServer Retrieve BFV EvalKeys from server
func GetBfvEvalKeysFromServer(serverURL string) (EvalKeys, error) {
	client := HttpsServer

	resp, err := client.Get(serverURL)
	if err != nil {
		return EvalKeys{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return EvalKeys{}, err
	}

	response := BfvEvalKeysResult{}
	if err := json.Unmarshal(body, &response); err != nil {
		return EvalKeys{}, err
	}

	var bfvEvalKeys EvalKeys
	if err := json.Unmarshal([]byte(response.EvalKeys), &bfvEvalKeys); err != nil {
		return EvalKeys{}, err
	}

	return bfvEvalKeys, nil
}

// SendComputationResultToServerCkks Send CKKS computation results to server and get a decrypted result
func SendComputationResultToServerCkks(url string, encryptedResult []byte) (float64, error) {
	data, err := json.Marshal(map[string][]byte{"encrypted_result": encryptedResult})
	if err != nil {
		return 0.0, err
	}

	client := HttpsServer

	resp, err := client.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return 0.0, err
	}
	defer resp.Body.Close()

	response := DecryptedResultResponseFloat{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0.0, err
	}

	return response.DecryptedResult, nil
}

// SendComputationResultToServerBfv Send BFV computation results to server and get a decrypted result
func SendComputationResultToServerBfv(url string, encryptedResult []byte) (int64, error) {
	data, err := json.Marshal(map[string][]byte{"encrypted_result": encryptedResult})
	if err != nil {
		return 0.0, err
	}

	client := HttpsServer

	resp, err := client.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return 0.0, err
	}
	defer resp.Body.Close()

	response := DecryptedResultResponseInt{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0.0, err
	}

	return response.DecryptedResult, nil
}

// handleGetCkksParams A request handler for CkksParams retrieving
func handleGetCkksParams(c *gin.Context) {
	paramsJSON, err := json.Marshal(CkksParams)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ckks serialization error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ckks_params": string(paramsJSON)})
}

// handleGetBfvParams A request handler for BfvParams retrieving
func handleGetBfvParams(c *gin.Context) {
	paramsJSON, err := json.Marshal(BfvParams)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "bfv serialization error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"bfv_params": string(paramsJSON)})
}

// handleDecryptCkks A request handler for decrypting a result of client calculations with CKKS
func handleDecryptCkks(c *gin.Context) {
	var req struct {
		EncryptedResult []byte `json:"encrypted_result"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	decResult, err := DecryptCKKS(req.EncryptedResult)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"decrypted_result": decResult})
}

// handleDecryptBfv A request handler for decrypting a result of client calculations with BFV
func handleDecryptBfv(c *gin.Context) {
	var req struct {
		EncryptedResult []byte `json:"encrypted_result"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	decResult, err := DecryptBFV(req.EncryptedResult)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"decrypted_result": decResult})
}

// handleGetBfvParams A request handler for CKKS EvalKeys retrieving
func handleGetEvalKeysCkks(c *gin.Context) {
	paramsJSON, err := json.Marshal(EvalKeysCkks)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ckks eval keys serialization error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ckks_eval_keys": string(paramsJSON)})
}

// handleGetBfvParams A request handler for BFV EvalKeys retrieving
func handleGetEvalKeysBfv(c *gin.Context) {
	paramsJSON, err := json.Marshal(EvalKeysBfv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "bfv eval keys serialization error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"bfv_eval_keys": string(paramsJSON)})
}
