package homomorphic_encryption_lib

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
	"net/http"
)

func SendComputationResult(url string, encryptedResult []byte) ([]byte, error) {
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
		DecryptedResult []byte `json:"decrypted_result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response.DecryptedResult, nil
}

func ServerHandler(sk *rlwe.SecretKey, ckksParams ckks.Parameters) *gin.Engine {
	r := gin.Default()

	r.POST("/compute", func(c *gin.Context) {
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
		decResult, err := DecryptCKKS(req.EncryptedResult, sk, ckksParams)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"decrypted_result": decResult})
	})

	return r
}
