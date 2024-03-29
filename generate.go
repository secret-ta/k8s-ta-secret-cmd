package k8stasecretcmd

import (
	"fmt"

	cryptomodule "github.com/secret-ta/k8s-ta-internal-crypto-library"
)

func execGenerateKeys(c cryptomodule.CryptoModule, opt Option) error {
	public, private, err := c.GeneratePublicPrivateKey()
	if err != nil {
		return err
	}

	publicStr := publicKeyFormat(public)

	err = createDirectoryIfNotExists(opt.OutputPath)
	if err != nil {
		return err
	}

	if err := writeStringToFile(opt.OutputPath, "private.key", privateKeyFormat(private)); err != nil {
		return err
	}

	if opt.SplitKey {
		bytes, err := c.SplitKey(private, opt.KeyParts, opt.KeyThreshold)
		if err != nil {
			return err
		}
		for i, key := range bytes {
			filename := fmt.Sprintf("private-%d.key", i)
			if err := writeStringToFile(opt.OutputPath, filename, privateKeyFormat(key)); err != nil {
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
