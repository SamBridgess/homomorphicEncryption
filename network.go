package homomorphic_encryption_lib

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/ldsec/lattigo/v2/ckks"
	"io"
	"net/http"
)

var (
	AesKey []byte = make([]byte, 32)
)

func ServerHandler() *gin.Engine {
	r := gin.Default()

	r.POST("/decrypt_computations", handleDecrypt)
	r.GET("/get_ckks_params", handleGetCkksParams)
	return r
}

func GetCKKSParamsFromServer(serverURL string) (ckks.Parameters, error) {
	resp, err := http.Get(serverURL)
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

func SendComputationResultToServer(url string, encryptedResult []byte) (float64, error) {
	data, err := json.Marshal(map[string][]byte{"encrypted_result": encryptedResult})
	if err != nil {
		return 0.0, err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return 0.0, err
	}
	defer resp.Body.Close()

	var response struct {
		DecryptedResult []byte `json:"decrypted_result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0.0, err
	}

	decryptedResultAes, _ := DecryptAES(response.DecryptedResult, AesKey)
	return BytesToFloat(decryptedResultAes), nil
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

	decResult, err := DecryptCKKS(req.EncryptedResult)

	decResultAes, _ := EncryptAES(FloatToBytes(decResult), AesKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"decrypted_result": decResultAes})
}
