package homomorphic_encryption_lib

import (
	"github.com/SamBridgess/homomorphic_encryption_lib/bfvMath"
	"github.com/SamBridgess/homomorphic_encryption_lib/ckksMath"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
)

// SetupClient Sets up CkksParams on client side and creates an Evaluator using
// newly set up CkksParams. Evaluation key is skipped for now
func SetupClient(ckksParams ckks.Parameters, bfvParams bfv.Parameters) {
	var EvalKey rlwe.EvaluationKey
	ckksMath.CkksEvaluator = ckks.NewEvaluator(CkksParams, EvalKey)
	ckksMath.CkksParams = ckksParams
	bfvMath.BfvEvaluator = bfv.NewEvaluator(BfvParams, EvalKey)
	bfvMath.BfvParams = bfvParams
}
