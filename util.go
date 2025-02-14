package homomorphic_encryption_lib

import "encoding/binary"

func FloatToBytes(f float64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(f))
	return buf
}

func BytesToFloat(b []byte) float64 {
	recoveredUint := binary.LittleEndian.Uint64(b)
	return float64(recoveredUint)
}
