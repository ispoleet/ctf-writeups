# Installation

1. Install [`tinygo`](https://github.com/tinygo-org/tinygo)
2. Patch `/usr/local/go/src/crypto/cipher/xor_amd64.go` with the following command:
    ```bash
    patch -p1 < xor.patch
    ```
3. Build `gocrygo` with the following command:
    ```bash
    tinygo build gocrygo.go
    strip gocrygo
    ```
