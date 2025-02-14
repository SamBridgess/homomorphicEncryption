package homomorphic_encryption_lib

import (
	"encoding/binary"
	"math"
)

func FloatToBytes(f float64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, math.Float64bits(f))
	return buf
}

func BytesToFloat(b []byte) float64 {
	recoveredUint := binary.LittleEndian.Uint64(b)
	return math.Float64frombits(recoveredUint)
}
