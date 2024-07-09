<img src="https://github.com/maceip/tee-bootstrap-ens/assets/804368/3f1aeb3a-468b-4522-bc3e-fe642d0d55ed" width="350"/>
</br>
<h1> bootstrapping trusted execution environments</h1>
a demo using gramine and ethereum name service (with gasless ccip offchain resolvers) to create stateless enclaves


#### bootstrap flow:

1) creates a new ethereum account
2) creates a human 'name'
3) reads the /dev/attestation pseudo hardware to get it's own MR_SIGNER and MR_ENCLAVE values
4) uses the CCIP-Read gateway and creates a new subdomain:
   - *{human-name}*.maceip.eth
        - with text records:
            - mr_signer
            - mr_enclave
         
## run it in SGX:
 _install gramine_
1) ```SGX=1 make```
2) ```SGX=1 make start-gramine-server```
3) an ens-tee is born! 👶 ```sonja-quigley.maceip.eth```
   
## demo resolve on-chain
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

## notes

1) _the [resolver contract](https://etherscan.io/address/0x33326e79248FbE36C4A0D88957cbA1e9a3a9731D#code) imlpements [ENSIP 10](https://docs.ens.domains/ensip/10) and [EIP 3668](https://eips.ethereum.org/EIPS/eip-3668), so your old ens resolver likely wont work_
2) ccip-read gateway tls cert is hard coded, this will be moved to an ENS query or [MTC](https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/) assertion in the future
3) enclave *_lineage_* / linkability is not yet implemented. Who's enclave is this? e.g., prove Eigenlayer AVS node operator "alice.eth" is the parent of encalve "betty-boop.maceip.eth"
4) the ens domain: maceip.eth will be swapped out for something more utilitarian

### ideas along the way
1) [pkarr](https://github.com/Nuhvi/pkarr)
2) [iroh-pkarr-ipns](https://github.com/n0-computer/iroh-experiments/blob/main/iroh-pkarr-naming-system/examples/cli.rs)
3) prolly-trees 
