package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	k8stasecretcmd "github.com/secret-ta/k8s-ta-secret-cmd"
)

var (
	help = flag.Bool("h", false, "show help")

	secretname = flag.String("name", "", "secret name")
	filename   = flag.String("filename", "", "file name")

	bits      = flag.Int("bits", 0, "key bits size")
	split     = flag.Bool("split", false, "split private key")
	parts     = flag.Int("parts", 1, "private key parts")
	threshold = flag.Int("threshold", 1, "private key threshold")

	output = flag.String("o", "", "output folder")

	node = flag.Int("node", 1, "node")

	usage = `
Encrypt secret util

k8stasecretcmd COMMAND_ARGS
	[-name SECRET_NAME]
	[-filename SECRET_FILE]
	[-bits KEY_BITS]
	[-split]
	[-parts KEY_PARTS]
	[-threshold KEYS_THRESHOLD]
	[-o OUTPUT_DIR]
	command

SECRET_NAME: kubernetes secret name
FILE_NAME: .env file name

[-split] split private key using shamir
KEY_PARTS: key part split
KEYS_THRESHOLD: key threshold
OUTPUT_DIR: output directory

example
	k8stasecretcmd -name tes -filename .env -o ./output create
`
)

func main() {
	flag.Parse()

	args := flag.Args()

	if *help || len(args) <= 0 {
		fmt.Println(usage)
		return
	}

	err := k8stasecretcmd.Exec(k8stasecretcmd.Option{
		Cmd: args[0],

		SecretName:     *secretname,
		SecretFileName: *filename,

		Bits:         *bits,
		SplitKey:     *split,
		KeyParts:     *parts,
		KeyThreshold: *threshold,

		OutputPath: *output,

		Node: *node,
	})

	if err != nil {
		if strings.HasPrefix(err.Error(), "v: ") {
			errstr := strings.TrimPrefix(err.Error(), "v: ")
			fmt.Fprintf(os.Stderr, "%s\n", errstr)
			return
		}
		if os.RemoveAll(*output); err != nil {
			panic(err.Error())
		}
		panic(err.Error())
	}
}
