package homomorphic_encryption_lib

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
)

func SendComputationResult(url string, encryptedResult []byte) ([]float64, error) {
	data, err := json.Marshal(map[string][]byte{"encrypted_result": encryptedResult})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response struct {
		DecryptedResult []float64 `json:"decrypted_result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response.DecryptedResult, nil
}

func ServerHandler() *gin.Engine {
	r := gin.Default()

	r.POST("/compute", handleDecrypt)
	r.GET("/get_ckks_params", handleGetCkksParams)
	return r
}
func handleGetCkksParams(c *gin.Context) {
	paramsJSON, err := json.Marshal(CkksParams)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ckks serialization error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ckks_params": string(paramsJSON)})
}

func handleDecrypt(c *gin.Context) {
	var req struct {
		EncryptedResult []byte `json:"encrypted_result"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	/*
		key, _ := GenKeyAES()
		plaintext, err := homomorphic_encryption_lib.DecryptAES(req.EncryptedResult, key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	*/
	decResult, err := DecryptCKKS(req.EncryptedResult)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"decrypted_result": decResult})
}
