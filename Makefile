wasm: main.wasm
	GOOS=js GOARCH=wasm go build -o main.wasm
serve: main.wasm
	python -m http.server 8080 --bind 127.0.0.1
clean:
	rm -f main.wasm
