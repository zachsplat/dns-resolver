package dns

import "math/rand"

func randID() uint16 {
	return uint16(rand.Intn(0xFFFF))
}
