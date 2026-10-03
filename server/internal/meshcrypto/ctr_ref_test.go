package meshcrypto

import "crypto/cipher"

func ctrRef(block cipher.Block, iv, in, out []byte) {
	cipher.NewCTR(block, iv).XORKeyStream(out, in)
}
