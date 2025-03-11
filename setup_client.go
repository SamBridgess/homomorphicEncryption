package homomorphic_encryption_lib

import (
	"github.com/SamBridgess/homomorphic_encryption_lib/bfvMath"
	"github.com/SamBridgess/homomorphic_encryption_lib/ckksMath"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
	"log"
)

// SetupClient Sets up CkksParams on client side and creates an Evaluator using
// newly set up CkksParams. Evaluation key is skipped for now
func SetupClient(ckksParams ckks.Parameters, bfvParams bfv.Parameters, ckksEvalKey rlwe.EvaluationKey, bfvEvalKey rlwe.EvaluationKey) {
	ckksMath.CkksParams = ckksParams
	ckksMath.CkksEvalkey = ckksEvalKey
	ckksMath.CkksEvaluator = ckks.NewEvaluator(ckksMath.CkksParams, ckksMath.CkksEvalkey)

	bfvMath.BfvParams = bfvParams
	bfvMath.BfvEvalKey = bfvEvalKey
	bfvMath.BfvEvaluator = bfv.NewEvaluator(bfvMath.BfvParams, bfvMath.BfvEvalKey)
	log.Println("Client setup successful")
}
