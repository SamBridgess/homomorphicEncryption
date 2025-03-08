package math

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
)

var CkksParams ckks.Parameters
var BfvParams bfv.Parameters
var Evaluator ckks.Evaluator
var EvalKey rlwe.EvaluationKey

// SetupClient Sets up CkksParams on client side and creates an Evaluator using
// newly set up CkksParams. Evaluation key is skipped for now
func SetupClient(ckksParams ckks.Parameters, bfvParams bfv.Parameters) {
	CkksParams = ckksParams
	BfvParams = bfvParams
	Evaluator = ckks.NewEvaluator(CkksParams, EvalKey)
}
