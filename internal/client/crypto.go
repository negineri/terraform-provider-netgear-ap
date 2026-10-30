package client

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"
)

// webUIKey is the fixed AES-256 key embedded in the web UI
// (/luci-static/resources/crypto.js). Secrets such as Wi-Fi passphrases and
// RADIUS secrets are exchanged with the device encrypted with this key using
// AES-ECB with PKCS#7 padding. This is obfuscation rather than protection.
var webUIKey = []byte("HuKylGfhLMj6Fo6D4kBjFAdpqV37UonN")

// encryptSecret reproduces aes_encrypt256() of the web UI.
func encryptSecret(plain string) string {
	block, err := aes.NewCipher(webUIKey)
	if err != nil {
		panic(err) // the key length is constant and valid
	}
	bs := block.BlockSize()
	pad := bs - len(plain)%bs
	data := append([]byte(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		block.Encrypt(out[i:i+bs], data[i:i+bs])
	}
	return base64.StdEncoding.EncodeToString(out)
}

// decryptSecret reproduces aes_decrypt256() of the web UI.
func decryptSecret(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("decoding secret: %w", err)
	}
	block, err := aes.NewCipher(webUIKey)
	if err != nil {
		return "", err
	}
	bs := block.BlockSize()
	if len(data) == 0 || len(data)%bs != 0 {
		return "", errors.New("decoding secret: invalid length")
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		block.Decrypt(out[i:i+bs], data[i:i+bs])
	}
	pad := int(out[len(out)-1])
	if pad == 0 || pad > bs || pad > len(out) || !bytes.Equal(out[len(out)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return "", errors.New("decoding secret: invalid padding")
	}
	return string(out[:len(out)-pad]), nil
}
