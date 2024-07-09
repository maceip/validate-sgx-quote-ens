package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"slices"

	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"time"

	ps "github.com/etaaa/Golang-Ethereum-Personal-Sign"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/lzap/deagon"
	ens "github.com/wealdtech/go-ens/v3"
	"tideland.dev/go/wait"
)

type CertStore struct {
	rootens        string
	rootensaddress string
	subdomains     []string
}

func NewCertStore() *CertStore {
	return &CertStore{rootens: "maceip.eth", rootensaddress: "0x0D8761dAad9aA860f33fdaF77150c99d0D2e1E25", subdomains: []string{""}}
}

const rootPEM = `
-----BEGIN CERTIFICATE-----
MIIEVzCCAj+gAwIBAgIRAIOPbGPOsTmMYgZigxXJ/d4wDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjQwMzEzMDAwMDAw
WhcNMjcwMzEyMjM1OTU5WjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCRTUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQNCzqK
a2GOtu/cX1jnxkJFVKtj9mZhSAouWXW0gQI3ULc/FnncmOyhKJdyIBwsz9V8UiBO
VHhbhBRrwJCuhezAUUE8Wod/Bk3U/mDR+mwt4X2VEIiiCFQPmRpM5uoKrNijgfgw
gfUwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
ATASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSfK1/PPCFPnQS37SssxMZw
i9LXDTAfBgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcB
AQQmMCQwIgYIKwYBBQUHMAKGFmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0g
BAwwCjAIBgZngQwBAgEwJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVu
Y3Iub3JnLzANBgkqhkiG9w0BAQsFAAOCAgEAH3KdNEVCQdqk0LKyuNImTKdRJY1C
2uw2SJajuhqkyGPY8C+zzsufZ+mgnhnq1A2KVQOSykOEnUbx1cy637rBAihx97r+
bcwbZM6sTDIaEriR/PLk6LKs9Be0uoVxgOKDcpG9svD33J+G9Lcfv1K9luDmSTgG
6XNFIN5vfI5gs/lMPyojEMdIzK9blcl2/1vKxO8WGCcjvsQ1nJ/Pwt8LQZBfOFyV
XP8ubAp/au3dc4EKWG9MO5zcx1qT9+NXRGdVWxGvmBFRAajciMfXME1ZuGmk3/GO
koAM7ZkjZmleyokP1LGzmfJcUd9s7eeu1/9/eg5XlXd/55GtYjAM+C4DG5i7eaNq
cm2F+yxYIPt6cbbtYVNJCGfHWqHEQ4FYStUyFnv8sjyqU8ypgZaNJ9aVcWSICLOI
E1/Qv/7oKsnZCWJ926wU6RqG1OYPGOi1zuABhLw61cuPVDT28nQS/e6z95cJXq0e
K1BcaJ6fJZsmbjRgD5p3mvEf5vdQM7MCEvU0tHbsx2I5mHHJoABHb8KVBgWp/lcX
GWiWaeOyB7RP+OfDtvi2OsapxXiV7vNVs7fMlrRjY1joKaqmmycnBvAq14AEbtyL
sVfOS66B8apkeFX2NY4XPEYV4ZSCe8VHPrdrERk2wILG3T/EGmSIkCYVUMSnjmJd
VQD9F6Na/+zmXCc=
-----END CERTIFICATE-----`
const googleRoot = `
-----BEGIN CERTIFICATE-----
MIIFYjCCBEqgAwIBAgIQd70NbNs2+RrqIQ/E8FjTDTANBgkqhkiG9w0BAQsFADBX
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UE
CxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIwMDYx
OTAwMDA0MloXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoT
GUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFIx
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAthECix7joXebO9y/lD63
ladAPKH9gvl9MgaCcfb2jH/76Nu8ai6Xl6OMS/kr9rH5zoQdsfnFl97vufKj6bwS
iV6nqlKr+CMny6SxnGPb15l+8Ape62im9MZaRw1NEDPjTrETo8gYbEvs/AmQ351k
KSUjB6G00j0uYODP0gmHu81I8E3CwnqIiru6z1kZ1q+PsAewnjHxgsHA3y6mbWwZ
DrXYfiYaRQM9sHmklCitD38m5agI/pboPGiUU+6DOogrFZYJsuB6jC511pzrp1Zk
j5ZPaK49l8KEj8C8QMALXL32h7M1bKwYUH+E4EzNktMg6TO8UpmvMrUpsyUqtEj5
cuHKZPfmghCN6J3Cioj6OGaK/GP5Afl4/Xtcd/p2h/rs37EOeZVXtL0m79YB0esW
CruOC7XFxYpVq9Os6pFLKcwZpDIlTirxZUTQAs6qzkm06p98g7BAe+dDq6dso499
iYH6TKX/1Y7DzkvgtdizjkXPdsDtQCv9Uw+wp9U7DbGKogPeMa3Md+pvez7W35Ei
Eua++tgy/BBjFFFy3l3WFpO9KWgz7zpm7AeKJt8T11dleCfeXkkUAKIAf5qoIbap
sZWwpbkNFhHax2xIPEDgfg1azVY80ZcFuctL7TlLnMQ/0lUTbiSw1nH69MG6zO0b
9f6BQdgAmD06yK56mDcYBZUCAwEAAaOCATgwggE0MA4GA1UdDwEB/wQEAwIBhjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTkrysmcRorSCeFL1JmLO/wiRNxPjAf
BgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzBgBggrBgEFBQcBAQRUMFIw
JQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnBraS5nb29nL2dzcjEwKQYIKwYBBQUH
MAKGHWh0dHA6Ly9wa2kuZ29vZy9nc3IxL2dzcjEuY3J0MDIGA1UdHwQrMCkwJ6Al
oCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMS9nc3IxLmNybDA7BgNVHSAENDAy
MAgGBmeBDAECATAIBgZngQwBAgIwDQYLKwYBBAHWeQIFAwIwDQYLKwYBBAHWeQIF
AwMwDQYJKoZIhvcNAQELBQADggEBADSkHrEoo9C0dhemMXoh6dFSPsjbdBZBiLg9
NR3t5P+T4Vxfq7vqfM/b5A3Ri1fyJm9bvhdGaJQ3b2t6yMAYN/olUazsaL+yyEn9
WprKASOshIArAoyZl+tJaox118fessmXn1hIVw41oeQa1v1vg4Fv74zPl6/AhSrw
9U5pCZEt4Wi4wStz6dTZ/CLANx8LZh1J7QJVj2fhMtfTJr9w4z30Z209fOU0iOMy
+qduBmpvvYuR7hZL6Dupszfnw0Skfths18dG9ZKb59UhvmaSGZRVbNQpsg3BZlvi
d0lIKO2d1xozclOzgjXPYovJJIultzkMu34qQb9Sz/yilrbCgj8=
-----END CERTIFICATE-----`
const certPEM = `
-----BEGIN CERTIFICATE-----
MIIDejCCAwCgAwIBAgISBI1BD7TP62VJpLP6BvIU0r1OMAoGCCqGSM49BAMDMDIx
CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF
NTAeFw0yNDA3MDgwOTI3MzVaFw0yNDEwMDYwOTI3MzRaMBgxFjAUBgNVBAMTDWNh
LmxvZ2luLmxpbW8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQDGQGui1u93R4X
iUkEN0HcPJUALteUVCwH13dBdTiTowQg4K9Nr/EgMcS5YJ+1Hwq5wxN2elskRQsX
69mtRNmso4ICDjCCAgowDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUF
BwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBR38DrrUO9qYBmi
2R1o1VhUu3G5IjAfBgNVHSMEGDAWgBSfK1/PPCFPnQS37SssxMZwi9LXDTBVBggr
BgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6Ly9lNS5vLmxlbmNyLm9yZzAi
BggrBgEFBQcwAoYWaHR0cDovL2U1LmkubGVuY3Iub3JnLzAYBgNVHREEETAPgg1j
YS5sb2dpbi5saW1vMBMGA1UdIAQMMAowCAYGZ4EMAQIBMIIBAwYKKwYBBAHWeQIE
AgSB9ASB8QDvAHYA7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZsAAAGQ
keJ0wwAABAMARzBFAiEAyBQ/YiVrtP85prbR9aFlKVeZQnhG/xTHs7fqgecDC7oC
IAXlzI1YCTzvEV4Sr4za8xnj6VWfXQ3wUcfCDlbb+zn1AHUASLDja9qmRzQP5WoC
+p0w6xxSActW3SyB2bu/qznYhHMAAAGQkeJ0vwAABAMARjBEAiBVy3hXHMb0XfRO
pxtQQ5KM0B4piuqMey6tBIEaiaeeIAIgUPUZLJ+oKxGdwpubiHo5vZdsvdVp1Lj6
wkF7pFwtlcEwCgYIKoZIzj0EAwMDaAAwZQIxAP4cWn8kLtS0yBJ5ZYIel2XRxDHe
vGHTPE9BOiyO/yHazg1Ynn7UxqdaKHacUud3YgIwLIc+aDXwmiaKstvbobAN4hVw
bSss9G/PBGNonX8I5V7hlsI3Roy5VxHsxgnwi/ph
-----END CERTIFICATE-----`

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

	userReportData := make([]byte, 64)
	err = ioutil.WriteFile("/dev/attestation/user_report_data", userReportData, 0644)
	if err != nil {
		fmt.Println("Error writing to /dev/attestation/user_report_data:", err)
		os.Exit(1)
	}

	report, err := ioutil.ReadFile("/dev/attestation/report")
	if err != nil {
		fmt.Println("Error reading /dev/attestation/report:", err)
		os.Exit(1)
	}

	fmt.Printf(" SGX report with size = %d and the following fields:\n", len(report))
	fmt.Printf("  ATTRIBUTES.FLAGS: %x  [ Debug bit: %t ]\n", report[48:56], report[48]&2 > 0)
	fmt.Printf("  ATTRIBUTES.XFRM:  %x\n", report[56:64])
	fmt.Printf("  MRENCLAVE:        %x\n", report[64:96])
	fmt.Printf("  MRSIGNER:         %x\n", report[128:160])
	fmt.Printf("  ISVPRODID:        %x\n", report[256:258])
	fmt.Printf("  ISVSVN:           %x\n", report[258:260])
	fmt.Printf("  REPORTDATA:       %x\n", report[320:352])
	fmt.Printf("                    %x\n", report[352:384])

	mr_enclave := report[64:96]
	mr_signer := report[128:160]
	enclave_data := slices.Concat(report[64:96], report[128:160])
	enclave_hash := crypto.Keccak256Hash(enclave_data)

	fmt.Println("my id: ", enclave_hash)

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	//privateKeyBytes := crypto.FromECDSA(privateKey)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	fmt.Println("Public Key:", hexutil.Encode(publicKeyBytes))

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	fmt.Println("Address:", address)

	myid := deagon.RandomName(deagon.NewLowercaseDashFormatter())

	name := myid + ".maceip.eth"
	owner := address

	fmt.Println(name)
	fmt.Println(owner)

	signature, err := ps.PersonalSign(name, privateKey)

	if err != nil {
		log.Fatal(err)
	}

	type Attestation struct {
		Ens string
		Pem string
	}
	type Sig struct {
		Hash    string `json:"hash"`
		Message string `json:"message"`
	}
	type Text struct {
		Mr_enclave string `json:"description"`
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
		Mr_enclave: "mr_enclave: " + hexutil.Encode(mr_enclave),
	}
	dataz := Payload{
		Name:      name,
		Owner:     address,
		Signature: sig,
		Texts:     text,
		Addresses: addressSixty,
	}

	attestation := Attestation{
		Ens: name,
		Pem: certPEM,
	}

	jsonData, err := json.Marshal(dataz)
	if err != nil {
		fmt.Printf("unable to marshal:  %s\n", err)
	}

	jsonAttestationData, err := json.Marshal(attestation)
	if err != nil {
		fmt.Printf("unable to marshal:  %s\n", err)
	}

	roots := x509.NewCertPool()
	ok = roots.AppendCertsFromPEM([]byte(googleRoot))
	if !ok {
		panic("failed to parse root certificate")
	}
	ok = roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}
	tlsConfig := &tls.Config{
		RootCAs: roots,
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		DNSName: "ca.login.limo",
		Roots:   roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}

	fmt.Printf("jsondata:  %s\n", bytes.NewBuffer(jsonData))
	fmt.Printf("jsondata:  %s\n", bytes.NewBuffer(jsonAttestationData))
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
	fmt.Println("got:  ", resp)

	defer resp.Body.Close()

	ethclient, err := ethclient.Dial("https://eth-mainnet.g.alchemy.com/v2/wsu3eqFqF2TtdHN1oGH9c6APK1kyYJxP")
	if err != nil {
		panic(err)
	}

	ensTicker := wait.MakeMaxIntervalsTicker(5*time.Millisecond, 10)

	ensQuery := func() (bool, error) {
		domain := name
		fmt.Println("resolving: " + domain)
		address, err := ens.Resolve(ethclient, domain)
		if err != nil {
			log.Fatal("ens.Resolve: ", err)
			return false, err
		}
		fmt.Printf("address is %s\n", address)
		return true, nil
	}

	wait.Poll(context.Background(), ensTicker, ensQuery)

}
