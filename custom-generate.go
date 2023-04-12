package k8stasecretcmd

import (
	"errors"
	"fmt"
	"strings"

	cryptomodule "github.com/secret-ta/k8s-ta-internal-crypto-library"
	"github.com/secret-ta/k8s-ta-internal-library/util"
)

func execCustomGenerateKeys(c cryptomodule.CryptoModule, opt Option) error {
	if opt.Node < 1 {
		return errors.New("minimum key generated for node is 1 node")
	}

	public, private, err := c.GeneratePublicPrivateKey()
	if err != nil {
		return err
	}

	publicStr := publicKeyFormat(public)

	err = createDirectoryIfNotExists(opt.OutputPath)
	if err != nil {
		return err
	}

	if err := writeStringToFile(opt.OutputPath, "public.pem", publicStr); err != nil {
		return err
	}

	if err := writeStringToFile(opt.OutputPath, "private.key", privateKeyFormat(private)); err != nil {
		return err
	}

	opt.KeyThreshold = 2
	opt.KeyParts = opt.Node * 2

	bytes, err := c.SplitKey(private, opt.KeyParts, opt.KeyThreshold)
	if err != nil {
		return err
	}

	for i := 0; i < len(bytes)-1; i += 2 {
		combinedKey := combineTwoKeysToBase64(bytes[i], bytes[i+1])
		i2 := i / 2
		filename := fmt.Sprintf("private-%d.key", i2)
		if err := writeStringToFile(opt.OutputPath, filename, privateKeyFormat2(combinedKey)); err != nil {
			return err
		}
	}

	fmt.Printf("keys successfully created on dir %s\n", opt.OutputPath)
	fmt.Printf("keep private key safe :)\n")

	return nil
}

func combineTwoKeysToBase64(a, b []byte) string {
	str1 := util.ByteToBase64String(a)
	str2 := util.ByteToBase64String(b)

	return fmt.Sprintf("%s.%s", str1, str2)
}

func privateKeyFormat2(private string) string {
	chunks := chunksString(private, 64)
	formats := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		strings.Join(chunks, "\n"),
		"-----END RSA PRIVATE KEY-----\n",
	}
	return strings.Join(formats, "\n")
}

func chunksString(s string, chunkSize int) []string {
	if len(s) == 0 {
		return nil
	}
	if chunkSize >= len(s) {
		return []string{s}
	}
	var chunks []string = make([]string, 0, (len(s)-1)/chunkSize+1)
	currentLen := 0
	currentStart := 0
	for i := range s {
		if currentLen == chunkSize {
			chunks = append(chunks, s[currentStart:i])
			currentLen = 0
			currentStart = i
		}
		currentLen++
	}
	chunks = append(chunks, s[currentStart:])
	return chunks
}
