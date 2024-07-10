package util

import (
	"bytes"
	"encoding/base64"
	"log"
	"io"
"io/ioutil"	
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
func DecompressAndDecodeBase64(content string) []byte{
	decoded, err := base64.StdEncoding.DecodeString(content)
br := bytes.NewReader(decoded)
		var decompressor io.Reader

			decompressor = brotli.NewReader(br)
			decompressed, err := ioutil.ReadAll(decompressor)
if err != nil {
				log.Printf("Error decompressing response body from %v",  err)
return []byte{}
			} else {
				return decompressed
			}

}
