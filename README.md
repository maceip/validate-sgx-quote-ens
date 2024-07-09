# bootstrapping trusted execution environments
a demo using gramine and ethereum name service (with ccip offchain resolvers) to create stateless enclaves


#### bootstrap flow:

1) creates a new ethereum account
2) creates a human 'name'
3) reads the /dev/attestation pseudo hardware to get it's own MR_SIGNER and MR_ENCLAVE values
4) uses the CCIP-Read gateway and creates a new subdomain:
   - {human-name}.maceip.eth
        - with text records:
            - mr_signer
            - mr_enclave
         
# run it in SGX:

1) ```SGX=1 make```
2) ```SGX=1 make start-gramine-server```
3) we have a ```sonja-quigley.maceip.eth```
   
# demo resolve on-chain

1) use the ens offchain-resolver repo
2) call it like:
```
pnpm start -i 1 --provider  https://eth-mainnet.g.alchemy.com/v2/wsu3eqFqF2TtdHN1oGH9c6APK1kyYJxP --registry 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e 'sonja-quigley.maceip.eth'
```
3) ret:
```
resolver address 0x33326e79248FbE36C4A0D88957cbA1e9a3a9731D
eth address 0x942855410cCa607E968261CcD2D156407671E795
mr_signer 0xf146b6fd6824a77832754aa144ae2761abcbc3ae65adcffce4973980be6c872d
mr_encalve 0xd4599e4a603c404e4aa8cda3e4ccfbb45870ddccb26ea2463adff11101d9c078
```

