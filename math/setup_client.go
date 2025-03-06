package math

import (
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
)

var CkksParams ckks.Parameters
var Evaluator ckks.Evaluator
var EvalKey rlwe.EvaluationKey

// SetupClient sets up CkksParams on client side and creates an Evaluator using
// newly set up CkksParams. Evaluation key is skipped for now
func SetupClient(ckksParams ckks.Parameters) {
	CkksParams = ckksParams
	Evaluator = ckks.NewEvaluator(CkksParams, EvalKey)
}
