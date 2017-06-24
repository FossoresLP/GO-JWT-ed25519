package jwt

import (
	"encoding/json"
	"os"
	"io/ioutil"
	"golang.org/x/crypto/ed25519"
)

type KeyData struct {
	PublicKey ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func readKeyData() (data KeyData) {
	keys, err := os.Open("keys.json")
	if (err == nil) {
		keysParser := json.NewDecoder(keys)
		err := keysParser.Decode(&data)
		if (err != nil) {
			data.PublicKey, data.PrivateKey, err = ed25519.GenerateKey(nil)
			if (err == nil) {
				jsonData, err := json.Marshal(&data)
				if (err == nil) {
					_ = ioutil.WriteFile("keys.json", jsonData, 0600)
				}
			}
		}
	} else {
		data.PublicKey, data.PrivateKey, err = ed25519.GenerateKey(nil)
		if (err == nil) {
			jsonData, err := json.Marshal(&data)
			if (err == nil) {
				_ = ioutil.WriteFile("keys.json", jsonData, 0600)
			}
		}
	}
	return
}
