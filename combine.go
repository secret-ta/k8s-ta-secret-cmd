package k8stasecretcmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	cryptomodule "github.com/secret-ta/k8s-ta-internal-library/crypto-module"
	"github.com/secret-ta/k8s-ta-internal-library/util"
)

func execCombineSecretsV2(c cryptomodule.CryptoModule, opt Option, filenames []string) error {
	for _, filename := range filenames {
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			return err
		}
	}

	keys := [][]byte{}

	for _, filename := range filenames {
		b, err := c.KeyFromFile(filename)
		if err != nil {
			return err
		}
		keys = append(keys, b)
	}

	combined, err := c.CombineKeys(keys)
	if err != nil {
		return err
	}

	err = createDirectoryIfNotExists(opt.OutputPath)
	if err != nil {
		return err
	}

	if err := writeStringToFile(opt.OutputPath, "private.key", privateKeyFormat(combined)); err != nil {
		return err
	}

	fmt.Printf("secrets successfully combined on dir %s\n", opt.OutputPath)
	fmt.Printf("keep private key safe :)\n")

	return nil
}

func execCombineSecrets(c cryptomodule.CryptoModule, opt Option) error {
	if opt.SecretFileName == "" {
		return errors.New("v: input file can't be empty")
	}
	if opt.OutputPath == "" {
		return errors.New("v: output dir can't be empty")
	}

	splitFile := strings.Split(opt.SecretFileName, ",")

	if len(splitFile) > 1 {
		return execCombineSecretsV2(c, opt, splitFile)
	}

	file, err := os.Open(opt.SecretFileName)
	if err != nil {
		return err
	}
	defer file.Close()

	keysByte := [][]byte{}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		key := scanner.Text()
		b, err := util.Base64StringToByte(key)
		if err != nil {
			return err
		}
		keysByte = append(keysByte, b)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	combined, err := c.CombineKeys(keysByte)
	if err != nil {
		return err
	}

	err = createDirectoryIfNotExists(opt.OutputPath)
	if err != nil {
		return err
	}

	if err := writeStringToFile(opt.OutputPath, "private.key", privateKeyFormat(combined)); err != nil {
		return err
	}

	fmt.Printf("secrets successfully combined on dir %s\n", opt.OutputPath)
	fmt.Printf("keep private key safe :)\n")

	return nil
}
