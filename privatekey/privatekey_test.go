package privatekey

import (
	"testing"
	"fmt"
)

func TestCreate(t *testing.T) {
	interactive := false
	keytypes := []string{"RSA","ECDSA"}
	keysizes := []int{128,192,256}
	algs := []string{"","AES128", "AES192", "AES256"}
	passphrase := "randompassword"
	for _, keytype := range keytypes {
		for _, keysize := range keysizes {
			for _, alg :=  range algs {
				keypath := fmt.Sprintf("./%s%d%s", keytype, keysize, alg) 
				Create(keytype, keysize, keypath, alg, passphrase, interactive)
			}
		}
	}
}