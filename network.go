package homomorphic_encryption_lib

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

// HttpsServer Basic https server configuration
var (
	HttpsServer = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}
)

// ServerHandler HTTP Handler
func ServerHandler() *gin.Engine {
	r := gin.Default()

	r.POST("/decrypt_computations_ckks", handleDecryptCkks)
	r.GET("/get_ckks_params", handleGetCkksParams)
	return r
}

// StartSecureServer Start HTTPS server. Port must be passed as is, without ':'
func StartSecureServer(port string, certFile string, keyFile string) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.POST("/decrypt_computations_ckks", handleDecryptCkks)
	r.GET("/get_ckks_params", handleGetCkksParams)

	r.POST("/decrypt_computations_bfv", handleDecryptBfv)
	r.GET("/get_bfv_params", handleGetBfvParams)

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

// SendComputationResultToServer_ckks Send CKKS computation results to server and get a decrypted result
func SendComputationResultToServer_ckks(url string, encryptedResult []byte) (float64, error) {
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

	var response struct {
		DecryptedResult float64 `json:"decrypted_result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0.0, err
	}

	return response.DecryptedResult, nil
}

// SendComputationResultToServer_bfv Send BFV computation results to server and get a decrypted result
func SendComputationResultToServer_bfv(url string, encryptedResult []byte) (int64, error) {
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

	var response struct {
		DecryptedResult int64 `json:"decrypted_result"`
	}
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

// handleDecrypt A request handler for decrypting a result of client calculations with CKKS
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
