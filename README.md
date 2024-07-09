<img src="https://github.com/maceip/tee-bootstrap-ens/assets/804368/3f1aeb3a-468b-4522-bc3e-fe642d0d55ed" width="350"/>
</br>
<h1> bootstrapping trusted execution environments</h1>
a demo using gramine and ethereum name service (with gasless ccip offchain resolvers) to create stateless enclaves


#### bootstrap flow:

1) creates a new ethereum account
2) creates a human 'name'
3) writes the eth address to the /dev/attestation/user_report_data pseudo hardware
4) reads /dev/attestation/quote, which contaains the intel-signed attestation
6) uses the CCIP-Read gateway and creates a new subdomain:
   - *{human-name}*.maceip.eth
        - with text records:
            - quote: a base64 encoded, brotli compressed blob containing the raw intel-signed attestation ( measurement ), which can be validated via Intel's root of trust.
         
## run it in SGX:
 _install gramine_
1) ```SGX=1 make```
2) ```SGX=1 make start-gramine-server```
3) an ens-tee is born! 👶 ```sonja-quigley.maceip.eth```
   
## demo resolve on-chain
1) use the ens offchain-resolver repo
2) call it like:
```
pnpm --silent start -i 1 --provider  https://eth-mainnet.g.alchemy.com/v2/wsu3eqFqF2TtdHN1oGH9c6APK1kyYJxP --registry 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e 'ola-keitt.maceip.eth' | base64 -d | brotli -d | openssl x509 -noout -text
```
3) ret:
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            95:6f:5d:cd:bd:1b:e1:e9:40:49:c9:d4:f4:33:ce:01:57:0b:de:54
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = Intel SGX Root CA, O = Intel Corporation, L = Santa Clara, ST = CA, C = US
        Validity
            Not Before: May 21 10:50:10 2018 GMT
            Not After : May 21 10:50:10 2033 GMT
        Subject: CN = Intel SGX PCK Platform CA, O = Intel Corporation, L = Santa Clara, ST = CA, C = US
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:35:20:7f:ee:dd:b5:95:74:8e:d8:2b:b3:a7:1c:
                    3b:e1:e2:41:ef:61:32:0c:68:16:e6:b5:c2:b7:1d:
                    ad:55:32:ea:ea:12:a4:eb:3f:94:89:16:42:9e:a4:
                    7b:a6:c3:af:82:a1:5e:4b:19:66:4e:52:65:79:39:
                    a2:d9:66:33:de
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                22:65:0C:D6:5A:9D:34:89:F3:83:B4:95:52:BF:50:1B:39:27:06:AC
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:https://certificates.trustedservices.intel.com/IntelSGXRootCA.der
            X509v3 Subject Key Identifier:
                95:6F:5D:CD:BD:1B:E1:E9:40:49:C9:D4:F4:33:CE:01:57:0B:DE:54
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
<snip>  
```

## notes

1) _the [resolver contract](https://etherscan.io/address/0x33326e79248FbE36C4A0D88957cbA1e9a3a9731D#code) imlpements [ENSIP 10](https://docs.ens.domains/ensip/10) and [EIP 3668](https://eips.ethereum.org/EIPS/eip-3668), so your old ens resolver likely wont work_
2) ccip-read gateway tls cert is hard coded, this will be moved to an ENS query or [MTC](https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/) assertion in the future
3) <s>enclave *_lineage_* / linkability is not yet implemented. Who's enclave is this? e.g., prove Eigenlayer AVS node operator "alice.eth" is the parent of encalve "betty-boop.maceip.eth"</s>
4) the ens domain: maceip.eth will be swapped out for something more utilitarian

### ideas along the way
1) [pkarr](https://github.com/Nuhvi/pkarr)
2) [iroh-pkarr-ipns](https://github.com/n0-computer/iroh-experiments/blob/main/iroh-pkarr-naming-system/examples/cli.rs)
3) prolly-trees 
