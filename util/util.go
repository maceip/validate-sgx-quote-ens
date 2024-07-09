package util

import (
	"bytes"
	"encoding/base64"
	"log"

	"github.com/andybalholm/brotli"
)

func CompressAndEncodeBase64(data []byte) string {
	buf := new(bytes.Buffer)
	compressor := brotli.NewWriterOptions(buf, brotli.WriterOptions{Quality: 100})

	_, err := compressor.Write(data)
	if err != nil {
		log.Fatal(err)
	}
	if err := compressor.Close(); err == nil {
		log.Println("compressor close")
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}
