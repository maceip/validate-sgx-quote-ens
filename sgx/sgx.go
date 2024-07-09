package sgx

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
"github.com/ethereum/go-ethereum/common/hexutil"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"
	"log/slog"
	"github.com/pkg/errors"
	"gopkg.in/restruct.v1"
)

const (
	HomeDir                        = "/opt/sqvs/"
	ConfigDir                      = "/etc/sqvs/"
	ExecLinkPath                   = "/usr/bin/sqvs"
	RunDirPath                     = "/run/sqvs"
	LogDir                         = "/var/log/sqvs/"
	LogFile                        = LogDir + "sqvs.log"
	SecLogFile                     = LogDir + "sqvs-security.log"
	HTTPLogFile                    = LogDir + "http.log"
	ConfigFile                     = "config.yml"
	DefaultTLSCertFile             = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyFile              = ConfigDir + "tls.key"
	TrustedJWTSigningCertsDir      = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir             = ConfigDir + "certs/trustedca/"
	TrustedSGXRootCAFile           = ConfigDir + "certs/trustedSGXRootCA.pem"
	ServiceRemoveCmd               = "systemctl disable sqvs"
	ServiceName                    = "SQVS"
	ExplicitServiceName            = "SGX Quote Verification Service"
	QuoteVerifierGroupName         = "QuoteVerifier"
	SQVSUserName                   = "sqvs"
	DefaultHTTPSPort               = 12000
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	DefaultSQVSTLSSan              = "127.0.0.1,localhost"
	DefaultSQVSTLSCn               = "SQVS TLS Certificate"
	DefaultSQVSSigningCertCn       = "SQVS QVL Response Signing Certificate"
	DefaultJwtValidateCacheKeyMins = 60
	SQVSLogLevel                   = "SQVS_LOGLEVEL"
	DefaultIncludeTokenValue       = true
	DefaultReadTimeout             = 30 * time.Second
	DefaultReadHeaderTimeout       = 10 * time.Second
	DefaultWriteTimeout            = 10 * time.Second
	DefaultIdleTimeout             = 1 * time.Second
	DefaultMaxHeaderBytes          = 1 << 20
	DefaultLogEntryMaxLength       = 300
	SGXRootCACertSubjectStr        = "CN=Intel SGX Root CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXInterCACertSubjectStr       = "CN=Intel SGX PCK Processor CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US|CN=Intel SGX PCK Platform CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXCRLIssuerStr                = "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX PCK Processor CA|C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX PCK Platform CA"
	SGXPCKCertificateSubjectStr    = "CN=Intel SGX PCK Certificate,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXTCBInfoSubjectStr           = "CN=Intel SGX TCB Signing,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	SGXQEInfoSubjectStr            = "CN=Intel SGX TCB Signing,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	MaxTcbLevels                   = 16
	MaxTCBCompLevels               = 18
	// At a minimum, Quote Should contain header, ecdsa report, attestation public key, signature, cert data
	MinQuoteSize        = 1020
	MaxQuoteSize        = (30 * 1024)
	MinCertDataSize     = 500
	MaxCertDataSize     = (4098 * 3)
	MinCertsInCertChain = 3 // PCK Leaf/Intermediate/Root CA certificates expected in quote
	FmspcLen            = 12
	PCKCertType         = 5
	PublicKeyLocation   = ConfigDir + "sqvs_signing_pub_key.pem"
	PrivateKeyLocation  = ConfigDir + "sqvs_signing_priv_key.pem"
)

const (
	ReportReserved1Bytes     = 28
	ReportReserved2Bytes     = 32
	ReportReserved3Bytes     = 96
	ReportReserved4Bytes     = 60
	EnclaveReportLength      = 384
	AttributeSize            = 16
	UserDataSize             = 20
	ReportDataSize           = 64
	QeVendorIdSize           = 16
	CPUsvnSize               = 16
	HashSize                 = 32
	Ecdsa256BitSignatureSize = 64
	Ecdsa256BitPubkeySize    = 64
)

type (
	SGXQuoteParser interface {
		GetSHA256Hash() []byte
		GetQeReportBlob() ([]byte, error)
		GetHeaderAndEnclaveReportBlob() ([]byte, error)
		GetQeReportAttributes() [AttributeSize]byte
		GetQeReportMiscSelect() uint32
		GetQeReportMrSigner() [HashSize]byte
		GetEnclaveMrSigner() [HashSize]byte
		GetQeReportProdID() uint16
		GetEnclaveReportProdID() uint16
		GetQeReportIsvSvn() uint16
		GetEnclaveReportIsvSvn() uint16
		GetQeReportMrEnclave() [32]byte
		GetEnclaveReportMrEnclave() [32]byte
		DumpSGXQuote()
		GetEnclaveReportSignature() []byte
		GetQeReportSignature() []byte
		GetAttestationPublicKey() []byte
		GetQuotePckCertObj() *x509.Certificate
		GetQuotePckCertInterCAList() []*x509.Certificate
		GetQuotePckCertRootCAList() []*x509.Certificate
		ParseQuoteCerts() error
		ParseRawECDSAQuote(decodedQuote []byte) error
	}
)
// Ecdsa Quote Header
type QuoteHeader struct {
	Version            uint16               /* (0) Version of Quote data structure */
	AttestationKeyType uint16               /* (2) Type of Attestation Key used by QE */
	TeeType            uint16               /* (4) TEE which generated the quote */
	Reserved           uint16               /* (6) Reserved */
	QeSvn              uint16               /* (8) Security Version Number of QE */
	PceSvn             uint16               /* (10) Security Version Nuumber of PCE */
	QeVendorId         [QeVendorIdSize]byte /* (12) Unique Identifier of QE Vendo  */
	UserData           [UserDataSize]byte   /* (28) Custom user-defined data */
}

// Enclave Report Body
type ReportBody struct {
	CPUSvn        [CPUsvnSize]byte           /* (0) Security Version of the CPU */
	MiscSelect    uint32                     /* (16) Which fields defined in SSA.MISC */
	Reserved1     [ReportReserved1Bytes]byte /* (20) */
	SgxAttributes [AttributeSize]byte        /* (48) Any special Capabilities the Enclave possess */
	MrEnclave     [HashSize]byte             /* (64) The value of the enclave's ENCLAVE measurement */
	Reserved2     [ReportReserved2Bytes]byte /* (96) */
	MrSigner      [HashSize]byte             /* (128) The value of the enclave's SIGNER measurement */
	Reserved3     [ReportReserved3Bytes]byte /* (160) */
	SgxIsvProdID  uint16                     /* (256) Product ID of the Enclave */
	SgxIsvSvn     uint16                     /* (258) Security Version of the Enclave */
	Reserved4     [ReportReserved4Bytes]byte /* (260) */
	ReportData    [ReportDataSize]byte       /* (320) Data provided by the user */
}

// QE Authentication Data
type QEAuthData struct {
	ParsedDataSize uint16
	Data           []byte
}

// QE Certification Data
type QECertData struct {
	Type           uint16
	ParsedDataSize uint32
	Data           []byte
}

type QuoteAuthData struct {
	// ECDSA signature over Header & Enclave Report calculated using ECDSA Attestation Key.
	EnclaveReportSignature [Ecdsa256BitSignatureSize]byte
	// Public part of ECDSA Attestation Key generated by Quoting Enclave
	AttestationPublicKey [Ecdsa256BitPubkeySize]byte
	// Report of the Quoting Enclave that generated the ECDSA Attestation Key
	QeReport ReportBody
	// ECDSA signature over QE Report calculated using Provisioning Certification Key
	QeReportSignature [Ecdsa256BitSignatureSize]byte
	// Variable-length data chosen by Quoting Enclave & signed by the Provisioning Certification Key
	QeAuthData QEAuthData
	// Data required to verify the QE Report Signature.
	QeCertData QECertData
}


type SgxQuoteParsed struct {
	Header             QuoteHeader
	EnclaveReport      ReportBody
	QuoteSignLen       uint32
	QuoteSignatureData QuoteAuthData
	PCKCert            *x509.Certificate
	RootCA             map[string]*x509.Certificate
	InterMediateCA     map[string]*x509.Certificate
}

type SkcBlobParsed struct {
	QuoteBlob []byte
}

func ParseQuoteBlob(rawBlob string) *SkcBlobParsed {
	decodedBlob, err := base64.StdEncoding.DecodeString(rawBlob)
	if err != nil {
		log.Fatal("Failed to Base64 Decode Quote")
		return nil
	}
	quoteSize := len(decodedBlob)
	if quoteSize < MinQuoteSize || quoteSize > MaxQuoteSize {
		log.Fatal("Quote Size is invalid. Seems to be an invalid ecdsa quote")
		return nil
	}
	parsedObj := new(SkcBlobParsed)
	parsedObj.QuoteBlob = make([]byte, quoteSize)
	copy(parsedObj.QuoteBlob, decodedBlob)
	return parsedObj
}

func (e *SkcBlobParsed) GetQuoteBlob() []byte {
	return e.QuoteBlob
}

func NewSGXQuoteParser(rawBlob []byte) SGXQuoteParser {
	parsedObj := new(SgxQuoteParsed)
	err := parsedObj.ParseRawECDSAQuote(rawBlob)
	if err != nil {
		log.Fatal("ParseEcdsaQuoteBlob: Raw SGX ECDSA Quote parsing error: ", err.Error())
		return nil
	}
	return parsedObj
}

func ParseEcdsaQuoteBlob(rawBlob []byte) *SgxQuoteParsed {
	parsedObj := new(SgxQuoteParsed)
	err := parsedObj.ParseRawECDSAQuote(rawBlob)
	if err != nil {
		log.Fatal("ParseEcdsaQuoteBlob: Raw SGX ECDSA Quote parsing error: ", err.Error())
		return nil
	}
	return parsedObj
}

func (e *SgxQuoteParsed) GetSHA256Hash() []byte {
	hashValue := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hashValue[i] = e.EnclaveReport.ReportData[i]
	}
	return hashValue
}

func (e *SgxQuoteParsed) GetQeReportBlob() ([]byte, error) {
	QeReportBlob, err := restruct.Pack(binary.LittleEndian, &e.QuoteSignatureData.QeReport)
	if err != nil {
		log.Fatal("Failed to extract enclave report from quote")
		return nil, errors.Wrap(err, "GetReportBlob: Failed to extract enclave report from quote")
	}

	return QeReportBlob, nil
}

func (e *SgxQuoteParsed) GetHeaderAndEnclaveReportBlob() ([]byte, error) {
	HeaderBlob, err := restruct.Pack(binary.LittleEndian, &e.Header)
	if err != nil {
		log.Fatal("Failed to extract enclave report from quote")
		return nil, errors.Wrap(err, "GetHeaderAndReportBlob: Failed to extract header from quote")
	}
	EnclaveReportBlob, err := restruct.Pack(binary.LittleEndian, &e.EnclaveReport)
	if err != nil {
		log.Fatal("Failed to extract enclave report from quote")
		return nil, errors.Wrap(err, "GetHeaderAndReportBlob: Failed to extract enclave report from quote")
	}

	return append(HeaderBlob, EnclaveReportBlob...), nil
}

func (e *SgxQuoteParsed) GetQeReportAttributes() [AttributeSize]byte {
	return e.QuoteSignatureData.QeReport.SgxAttributes
}

func (e *SgxQuoteParsed) GetQeReportMiscSelect() uint32 {
	return e.QuoteSignatureData.QeReport.MiscSelect
}

func (e *SgxQuoteParsed) GetQeReportMrSigner() [HashSize]byte {
	return e.QuoteSignatureData.QeReport.MrSigner
}

func (e *SgxQuoteParsed) GetEnclaveMrSigner() [HashSize]byte {
	return e.EnclaveReport.MrSigner
}

func (e *SgxQuoteParsed) GetQeReportProdID() uint16 {
	return e.QuoteSignatureData.QeReport.SgxIsvProdID
}

func (e *SgxQuoteParsed) GetEnclaveReportProdID() uint16 {
	return e.EnclaveReport.SgxIsvProdID
}

func (e *SgxQuoteParsed) GetQeReportIsvSvn() uint16 {
	return e.QuoteSignatureData.QeReport.SgxIsvSvn
}

func (e *SgxQuoteParsed) GetEnclaveReportIsvSvn() uint16 {
	return e.EnclaveReport.SgxIsvSvn
}

func (e *SgxQuoteParsed) GetQeReportMrEnclave() [32]byte {
	return e.QuoteSignatureData.QeReport.MrEnclave
}

func (e *SgxQuoteParsed) GetEnclaveReportMrEnclave() [32]byte {
	return e.EnclaveReport.MrEnclave
}

func (e *SgxQuoteParsed) DumpSGXQuote() {
	slog.Info("Version = ", e.Header.Version)
	slog.Info("Attestation Key Type = ", e.Header.AttestationKeyType)
	slog.Info("Tee Type = ", e.Header.TeeType)
	slog.Info("QeSvn = ", e.Header.QeSvn)
	slog.Info("PceSvn = ", e.Header.PceSvn)

	slog.Info("QE Report CPUSvn = %x", e.QuoteSignatureData.QeReport.CPUSvn)
	slog.Info("QE Report MiscSelect = %x", e.QuoteSignatureData.QeReport.MiscSelect)
	slog.Info("QE Report SgxAttributes = %x", e.QuoteSignatureData.QeReport.SgxAttributes)
	slog.Info("QE Report MrEnclave = %x", e.QuoteSignatureData.QeReport.MrEnclave)
	slog.Info("QE Report MrSigner = %x", e.QuoteSignatureData.QeReport.MrSigner)
	slog.Info("QE Report IsvProdID = %x", e.QuoteSignatureData.QeReport.SgxIsvProdID)
	slog.Info("QE Report IsvSvn = ", e.QuoteSignatureData.QeReport.SgxIsvSvn)

	slog.Info("Enclave Report CPUSvn = %x", e.EnclaveReport.CPUSvn)
	slog.Info("Enclave Report MiscSelect = %x", e.EnclaveReport.MiscSelect)
	slog.Info("Enclave Report SgxAttributes = %x", e.EnclaveReport.SgxAttributes)
	slog.Info("Enclave Report MrEnclave = %x", hexutil.Encode(e.EnclaveReport.MrEnclave[:]))
	slog.Info("Enclave Report MrSigner = %x", e.EnclaveReport.MrSigner)
	slog.Info("Enclave Report IsvProdID = %x", e.EnclaveReport.SgxIsvProdID)
	slog.Info("Enclave Report IsvSvn = ", e.EnclaveReport.SgxIsvSvn)

	slog.Info("QE Report Signature = %x", e.QuoteSignatureData.QeReportSignature)
	slog.Info("ECDSA Attestation PublicKey = %x", e.QuoteSignatureData.AttestationPublicKey)
	slog.Info("Enclave Report Signature = %x", e.QuoteSignatureData.EnclaveReportSignature)

	slog.Info("Auth Data Size = %v", e.QuoteSignatureData.QeAuthData.ParsedDataSize)
	slog.Info("Cert Data Type = %v", e.QuoteSignatureData.QeCertData.Type)
	slog.Info("Cert Data Size = %v", e.QuoteSignatureData.QeCertData.ParsedDataSize)
}

func (e *SgxQuoteParsed) GetEnclaveReportSignature() []byte {
	Signature := make([]byte, Ecdsa256BitSignatureSize)
	copy(Signature, e.QuoteSignatureData.EnclaveReportSignature[:])
	return Signature
}

func (e *SgxQuoteParsed) GetQeReportSignature() []byte {
	Signature := make([]byte, Ecdsa256BitSignatureSize)
	copy(Signature, e.QuoteSignatureData.QeReportSignature[:])
	return Signature
}

func (e *SgxQuoteParsed) GetAttestationPublicKey() []byte {
	attestPublicKey := make([]byte, Ecdsa256BitPubkeySize)
	copy(attestPublicKey, e.QuoteSignatureData.AttestationPublicKey[:])
	return attestPublicKey
}

func (e *SgxQuoteParsed) GetQuotePckCertObj() *x509.Certificate {
	return e.PCKCert
}

func (e *SgxQuoteParsed) GetQuotePckCertInterCAList() []*x509.Certificate {
	interMediateCAArr := make([]*x509.Certificate, len(e.InterMediateCA))
	var i int
	for _, v := range e.InterMediateCA {
		interMediateCAArr[i] = v
		i++
	}
	return interMediateCAArr
}

func (e *SgxQuoteParsed) GetQuotePckCertRootCAList() []*x509.Certificate {
	rootCAArr := make([]*x509.Certificate, len(e.RootCA))
	var i int
	for _, v := range e.RootCA {
		rootCAArr[i] = v
		i++
	}
	return rootCAArr
}

func (e *SgxQuoteParsed) ParseQuoteCerts() error {
	if e.QuoteSignatureData.QeCertData.Type != PCKCertType {
		return errors.New(fmt.Sprintf("Invalid Certificate type in Quote Info: %d", e.QuoteSignatureData.QeCertData.Type))
	}

	certs := strings.SplitAfterN(string(e.QuoteSignatureData.QeCertData.Data), "-----END CERTIFICATE-----",
		strings.Count(string(e.QuoteSignatureData.QeCertData.Data), "-----END CERTIFICATE-----"))

	numCerts := len(certs)
	if numCerts < MinCertsInCertChain {
		return errors.New("ParseQuoteCerts: Cert chain should contain atleast 3 certificates")
	}
	var pckCertCount, intermediateCACount, rootCACount int

	e.RootCA = make(map[string]*x509.Certificate)
	e.InterMediateCA = make(map[string]*x509.Certificate)
	for i := 0; i < numCerts; i++ {
		block, _ := pem.Decode([]byte(certs[i]))
		if block == nil {
			return errors.New("ParseQuoteCerts: error while decoding PCK Certchain in Quote")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatal("ParseCertificate error: ")
			return errors.Wrap(err, "ParseQuoteCerts: ParseCertificate error")
		}

		if strings.Contains(cert.Subject.String(), "CN=Intel SGX PCK Certificate") {
			pckCertCount++
			e.PCKCert = cert
		}

		if strings.Contains(cert.Subject.String(), "CN=Intel SGX Root CA") {
			rootCACount++
			e.RootCA[cert.Subject.String()] = cert
		}

		if strings.Contains(cert.Subject.String(), "CN=Intel SGX PCK Processor CA") ||
			strings.Contains(cert.Subject.String(), "CN=Intel SGX PCK Platform CA") {
			intermediateCACount++
			e.InterMediateCA[cert.Subject.String()] = cert
		}
		slog.Debug("Cert[", i, "]Issuer:", cert.Issuer.String(), ", Subject:", cert.Subject.String())
	}

	if pckCertCount == 0 || rootCACount == 0 || intermediateCACount == 0 {
		return errors.New(fmt.Sprintf("Quote Certificate Data invalid count: Pck Cert Count:%d, IntermediateCA Count:%d, RootCA Count:%d", pckCertCount, intermediateCACount, rootCACount))
	}

	slog.Info(fmt.Sprintf("Quote Certificate Data Info: Pck Cert Count:%d, IntermediateCA Count:%d, RootCA Count:%d", pckCertCount, intermediateCACount, rootCACount))
	return nil
}

func (e *SgxQuoteParsed) ParseRawECDSAQuote(decodedQuote []byte) error {
	err := restruct.Unpack(decodedQuote[:], binary.LittleEndian, &e.Header)
	if err != nil {
		log.Fatal("Failed to extract header from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract header from quote")
	}

	// Invoke golang in-built recover() function to recover from the panic
	// recover function will receive the error from out of bound slice access
	// and will prevent the program from crashing
	defer func() {
		if perr := recover(); perr != nil {
			log.Fatal("ParseRawECDSAQuote: slice out of bound access")
		}
	}()

	// Enclave Report Starts at offset of 48 bytes after the quote header
	encReportStart := 48
	err = restruct.Unpack(decodedQuote[encReportStart:], binary.LittleEndian, &e.EnclaveReport)
	if err != nil {
		log.Fatal("Failed to extract Enclave Report from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract Enclave Report from quote")
	}

	// Quote Auth Data Starts at offset of Quote Header Size (48 bytes) + Enclave Report Size (384 Bytes) +
	// Quote Signature Data length (4 bytes)
	// Quote Auth Data consists of enclave report, signature for Enclave report, its public key
	// and QE enclave reprt signature
	// Quote Auth Data Size is 576 bytes
	quoteAuthStart := encReportStart + EnclaveReportLength + 4
	err = restruct.Unpack(decodedQuote[quoteAuthStart:], binary.LittleEndian, &e.QuoteSignatureData)
	if err != nil {
		log.Fatal("Failed to extract Quote Signature Data from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract Code Signature Data from quote")
	}

	// QE Auth Data Starts after Quote Auth Data (576 Bytes)
	qeAuthStart := quoteAuthStart + 576
	err = restruct.Unpack(decodedQuote[qeAuthStart:], binary.LittleEndian, &e.QuoteSignatureData.QeAuthData)
	if err != nil {
		log.Fatal("Failed to extract quote auth data from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract quote auth data from quote")
	}

	// QE Cert Data Starts after QE Auth Data (34 Bytes)
	qeCertStart := qeAuthStart + 34
	err = restruct.Unpack(decodedQuote[qeCertStart:], binary.LittleEndian, &e.QuoteSignatureData.QeCertData)
	if err != nil {
		log.Fatal("Failed to extract certification data from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract certification data from  quote")
	}

	certDataSize := e.QuoteSignatureData.QeCertData.ParsedDataSize
	if certDataSize < MinCertDataSize || certDataSize > MaxCertDataSize {
		log.Fatal("Failed to extract certification data from quote")
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to extract certification data from  quote")
	}

	// QE Cert Data starts at offset 1046. First two bytes denote Cert type
	// next four bytes denote the size of the certificate chain that follows
	// at offset 1052, the certificate chain starts
	certChainStart := qeCertStart + 6
	e.QuoteSignatureData.QeCertData.Data = make([]byte, e.QuoteSignatureData.QeCertData.ParsedDataSize)
	copy(e.QuoteSignatureData.QeCertData.Data, decodedQuote[certChainStart:])

	err = e.ParseQuoteCerts()
	if err != nil {
		return errors.Wrap(err, "ParseRawECDSAQuote: Failed to Parse PCK certificates in Quote")
	}
	return nil
}


