package k8stasecretcmd

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/pkg/errors"
	cryptomodule "github.com/secret-ta/k8s-ta-internal-library/crypto-module"
	"github.com/secret-ta/k8s-ta-internal-library/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sJson "k8s.io/apimachinery/pkg/runtime/serializer/json"
)

func createDirectoryIfNotExists(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return err
		}
	}
	return nil
}

func removeIndex[T any](s []T, index int) []T {
	ret := make([]T, 0)
	ret = append(ret, s[:index]...)
	return append(ret, s[index+1:]...)
}

func readFileString(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	strs := []string{}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		strs = append(strs, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return strings.Join(strs, ""), nil
}

func privateKeyFormat(private []byte) string {
	str := util.ByteToBase64String(private)
	chunks := chunksString(str, 64)
	return strings.Join(chunks, "\n") + "\n"
}

func writeStringToFile(path, name, content string) (err error) {
	f1, err := os.Create(filepath.Join(path, name))
	if err != nil {
		return
	}

	defer f1.Close()

	_, err = f1.WriteString(content)
	if err != nil {
		return
	}

	return nil
}

func getPrivateKeySecrets(opt Option, privateKeys [][]byte) ([]byte, []privateKeyData) {
	r := rand.New(rand.NewSource(time.Now().Unix()))
	randIdx := r.Intn(len(privateKeys))
	randSecret := privateKeys[randIdx]
	newPrivateKeys := removeIndex(privateKeys, randIdx)

	out := []privateKeyData{}

	for i, key := range newPrivateKeys {
		obj := createPrivateKeySecretObj(opt, key, i)
		out = append(out, privateKeyData{
			name:             obj.Name,
			kubernetesSecret: obj,
			key:              key,
		})
	}

	return randSecret, out
}

func createPrivateKeys(c cryptomodule.CryptoModule, opt Option, privateKey []byte) ([][]byte, error) {
	if !opt.SplitKey {
		return [][]byte{privateKey}, nil
	}
	keys, err := c.SplitKey(privateKey, opt.KeyParts, opt.KeyThreshold)
	if err != nil {
		return nil, errors.Wrap(err, "error creating split keys")
	}

	return keys, nil
}

func createPrivateKeySecretObj(opt Option, privateKey []byte, i int) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-private-%d", opt.SecretName, i),
			Annotations: map[string]string{
				"should-encrypt": "false",
				"is-secret-key":  "true",
			},
		},
		Data: map[string][]byte{
			"secret": privateKey,
		},
		Type: corev1.SecretTypeOpaque,
	}
}

func getSecret(opt Option, b64PublicKey string, envMap map[string]string) *corev1.Secret {
	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: opt.SecretName,
			Annotations: map[string]string{
				"public-key":     string(b64PublicKey),
				"should-encrypt": "true",
			},
		},
		Data: map[string][]byte{},
		Type: corev1.SecretTypeOpaque,
	}

	for key, value := range envMap {
		secret.Data[key] = []byte(value)
	}

	return secret
}

func kubernetesObjToYaml(serializer *k8sJson.Serializer, obj runtime.Object) (string, error) {
	buf := new(strings.Builder)
	err := serializer.Encode(obj, buf)

	if err != nil {
		return "", errors.Wrap(err, "failed parsing yaml")
	}

	return buf.String(), nil
}

func parseFile(filename string) (envMap map[string]string, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()

	return godotenv.Parse(file)
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
