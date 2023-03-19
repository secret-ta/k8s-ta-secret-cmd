package k8stasecretcmd

import (
	"encoding/pem"
	"fmt"

	cryptomodule "github.com/secret-ta/k8s-ta-internal-library/crypto-module"
)

func execGenerateKeys(c cryptomodule.CryptoModule, opt Option) error {
	public, private, err := c.GeneratePublicPrivateKey()
	if err != nil {
		return err
	}

	publicStr := string(
		pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: public,
		}),
	)

	err = createDirectoryIfNotExists(opt.OutputPath)
	if err != nil {
		return err
	}

	if !opt.SplitKey {
		privateStr := string(
			pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: private,
			}),
		)
		if err := writeStringToFile(opt.OutputPath, "private.key", privateStr); err != nil {
			return err
		}
	} else {
		bytes, err := c.SplitKey(private, opt.KeyParts, opt.KeyThreshold)
		if err != nil {
			return err
		}
		for i, key := range bytes {
			privateStr := string(
				pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: key,
				}),
			)
			filename := fmt.Sprintf("private-%d.key", i)
			if err := writeStringToFile(opt.OutputPath, filename, privateStr); err != nil {
				return err
			}
		}
	}

	if err := writeStringToFile(opt.OutputPath, "public.pem", publicStr); err != nil {
		return err
	}

	fmt.Printf("keys successfully created on dir %s\n", opt.OutputPath)
	fmt.Printf("keep private key safe :)\n")

	return nil
}
