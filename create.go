package k8stasecretcmd

import (
	"fmt"

	"github.com/pkg/errors"
	cryptomodule "github.com/secret-ta/k8s-ta-internal-crypto-library"
	"github.com/secret-ta/k8s-ta-internal-library/util"
	k8sJson "k8s.io/apimachinery/pkg/runtime/serializer/json"
)

func execCreateSecrets(c cryptomodule.CryptoModule, opt Option) error {
	if opt.SecretName == "" || opt.SecretFileName == "" {
		return errors.New("v: secret name or secret file name can't be empty")
	}

	if opt.OutputPath == "" {
		return errors.New("v: output dir can't be empty")
	}

	public, private, err := c.GeneratePublicPrivateKey()
	if err != nil {
		return err
	}

	privateKeys, err := createPrivateKeys(c, opt, private)
	if err != nil {
		return err
	}

	b64Public := util.ByteToBase64String(public)

	envMap, err := parseFile(opt.SecretFileName)
	if err != nil {
		return err
	}

	actualSecret := getSecret(opt, b64Public, envMap)
	privateKeyToKeep, privateKeysSecrets := getPrivateKeySecrets(opt, privateKeys)

	if err != nil {
		err = errors.Wrap(err, "failed parsing yaml")
		return err
	}

	err = createDirectoryIfNotExists(opt.OutputPath)
	if err != nil {
		return err
	}

	serializer := k8sJson.NewSerializerWithOptions(
		k8sJson.DefaultMetaFactory, nil, nil,
		k8sJson.SerializerOptions{
			Yaml:   true,
			Pretty: true,
			Strict: true,
		},
	)

	secretYaml, err := kubernetesObjToYaml(serializer, actualSecret)
	if err != nil {
		return err
	}
	if err := writeStringToFile(opt.OutputPath, actualSecret.Name+".secret.yaml", secretYaml); err != nil {
		return err
	}

	for _, secret := range privateKeysSecrets {
		secretYaml, err := kubernetesObjToYaml(serializer, secret.kubernetesSecret)
		if err != nil {
			return err
		}
		if err := writeStringToFile(opt.OutputPath, secret.name+".secret.yaml", secretYaml); err != nil {
			return err
		}
		if err := writeStringToFile(opt.OutputPath, secret.name+".key", privateKeyFormat(secret.key)); err != nil {
			return err
		}
	}

	if err := writeStringToFile(opt.OutputPath, "private.key", privateKeyFormat(privateKeyToKeep)); err != nil {
		return err
	}

	fmt.Printf("secrets successfully created on dir %s\n", opt.OutputPath)
	fmt.Printf("keep private key safe :)\n")

	return nil
}
