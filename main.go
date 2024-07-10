package main

import (
	"fmt"
    "syscall/js"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/maceip/tee-bootstrap-ens/sgx"
	"github.com/maceip/tee-bootstrap-ens/util"
)

func jsPI() js.Func {
    return js.FuncOf(func(this js.Value, args []js.Value) any {
        if len(args) != 1 {
            return "Invalid no of arguments passed"
        }
        samples := args[0].String()
	println(samples)
        return verif(samples)
    })
}

func main() {
    js.Global().Set("jsPI", jsPI())
    <-make(chan bool)
}


func verif(samples string) string{
	d := util.DecompressAndDecodeBase64(samples)
	parsedObj := sgx.ParseEcdsaQuoteBlob(d)
	signedMrEnclave := parsedObj.GetEnclaveReportMrEnclave()
	parseQuoteCerts := parsedObj.ParseQuoteCerts()
	if parseQuoteCerts != nil {
                return ""
	}

	fmt.Println("VALID: mr_enclave: ", hexutil.Encode(signedMrEnclave[:]))
	return  hexutil.Encode(signedMrEnclave[:])
	}
