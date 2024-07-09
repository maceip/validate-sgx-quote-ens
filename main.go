package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/lzap/deagon"
	"github.com/maceip/tee-bootstrap-ens/cert"
	tc "github.com/maceip/tee-bootstrap-ens/crypto"
	"github.com/maceip/tee-bootstrap-ens/sgx"
	"github.com/maceip/tee-bootstrap-ens/util"
)

func main() {
	if _, err := os.Stat("/dev/attestation/report"); os.IsNotExist(err) {
		fmt.Println("Cannot find `/dev/attestation/report`; are you running under SGX?")
		os.Exit(1)
	}

	myTargetInfo, err := ioutil.ReadFile("/dev/attestation/my_target_info")
	if err != nil {
		fmt.Println("Error reading /dev/attestation/my_target_info:", err)
		os.Exit(1)
	}

	err = ioutil.WriteFile("/dev/attestation/target_info", myTargetInfo, 0644)
	if err != nil {
		fmt.Println("Error writing to /dev/attestation/target_info:", err)
		os.Exit(1)
	}

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	fmt.Println("Public Key:", hexutil.Encode(publicKeyBytes))

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	fmt.Println("Address:", address)

	err = ioutil.WriteFile("/dev/attestation/user_report_data", []byte(address), 0644)
	if err != nil {
		fmt.Println("Error writing to /dev/attestation/user_report_data:", err)
		os.Exit(1)
	}

	quote, err := ioutil.ReadFile("/dev/attestation/quote")
	if err != nil {
		fmt.Println("Error reading /dev/attestation/quote:", err)
		os.Exit(1)
	}

	fmt.Printf("SGX quote with size = %d and the following fields:\n", len(quote))
	fmt.Printf("  ATTRIBUTES.FLAGS: %x  [ Debug bit: %t ]\n", quote[96:104], quote[96]&2 > 0)
	fmt.Printf("  ATTRIBUTES.XFRM:  %x\n", quote[104:112])
	fmt.Printf("  MRENCLAVE:        %x\n", quote[112:144])
	fmt.Printf("  MRSIGNER:         %x\n", quote[176:208])
	fmt.Printf("  ISVPRODID:        %x\n", quote[304:306])
	fmt.Printf("  ISVSVN:           %x\n", quote[306:308])
	fmt.Printf("  quoteDATA:       %x\n", quote[368:400])
	fmt.Printf("                    %x\n", quote[400:432])

	parsedObj := sgx.ParseEcdsaQuoteBlob(quote)
	signedMrEnclave := parsedObj.GetEnclaveReportMrEnclave()
	parseQuoteCerts := parsedObj.ParseQuoteCerts()
	if parseQuoteCerts != nil {
		log.Fatal("intel root ca verification failed on quote")
	}

	fmt.Println("mr_enclave: ", hexutil.Encode(signedMrEnclave[:]))

	compressedQuote := util.CompressAndEncodeBase64(quote)

	myID := deagon.RandomName(deagon.NewLowercaseDashFormatter())
	name := myID + ".maceip.eth"

	fmt.Println("created: ", name)

	signature, err := tc.PersonalSign(name, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	type Sig struct {
		Hash    string `json:"hash"`
		Message string `json:"message"`
	}
	type Text struct {
		CompressedQuote string `json:"quote"`
	}
	type Address struct {
		Sixty string `json:"60"`
	}

	type Payload struct {
		Name      string  `json:"name"`
		Owner     string  `json:"owner"`
		Addresses Address `json:"addresses"`
		Texts     Text    `json:"texts"`
		Signature Sig     `json:"signature"`
	}

	sig := Sig{
		Hash:    signature,
		Message: name,
	}

	addressSixty := Address{
		Sixty: address,
	}
	text := Text{
		CompressedQuote: compressedQuote,
	}
	dataz := Payload{
		Name:      name,
		Owner:     address,
		Signature: sig,
		Texts:     text,
		Addresses: addressSixty,
	}

	jsonData, err := json.Marshal(dataz)
	if err != nil {
		fmt.Printf("unable to marshal:  %s\n", err)
	}

	roots := x509.NewCertPool()
	ok = roots.AppendCertsFromPEM([]byte(cert.GoogleRoot))
	if !ok {
		panic("failed to parse root certificate")
	}
	ok = roots.AppendCertsFromPEM([]byte(cert.RootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}
	tlsConfig := &tls.Config{
		RootCAs: roots,
	}

	block, _ := pem.Decode([]byte(cert.CertPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		DNSName: "ca.login.limo",
		Roots:   roots,
	}

	if _, err := certificate.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", "https://ens-gateway.exoskel.workers.dev/set", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("unable to post:  %s\n", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("unable to set:  %s\n", err)
	}

	defer resp.Body.Close()

}
