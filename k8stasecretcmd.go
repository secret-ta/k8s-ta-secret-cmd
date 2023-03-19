package k8stasecretcmd

import (
	"strings"

	"github.com/pkg/errors"
	cryptomodule "github.com/secret-ta/k8s-ta-internal-library/crypto-module"

	corev1 "k8s.io/api/core/v1"
)

type (
	Option struct {
		Cmd string

		SecretName     string
		SecretFileName string

		Bits         int
		SplitKey     bool
		KeyParts     int
		KeyThreshold int

		OutputPath string
	}

	privateKeyData struct {
		name             string
		key              []byte
		kubernetesSecret *corev1.Secret
	}
)

func Exec(opt Option) error {
	c := cryptomodule.NewCryptoModule(&cryptomodule.Option{
		KeyBits: opt.Bits,
	})

	switch strings.ToLower(opt.Cmd) {
	case "create", "update":
		return execCreateSecrets(c, opt)
	case "combine":
		return execCombineSecrets(c, opt)
	case "generate":
		return execGenerateKeys(c, opt)
	}

	return errors.New("unsupported command")
}
