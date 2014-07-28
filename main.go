// https://www.passwordchameleon.com/chameleon.js
package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	
	"github.com/atotto/clipboard"
	"code.google.com/p/gopass"
)

func generate(secretpassword, sitename string) string {
	input := []byte(secretpassword + ":" + sitename)
	pwd := &bytes.Buffer{}
	encoder := base64.NewEncoder(base64.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789?!#@&$"), pwd)
	h := sha1.New()
	h.Write(input)
	s := h.Sum(nil)
	encoder.Write(s)
	encoder.Close()
	return ensurenumberandletter(pwd.String()[:10])
}

func ensurenumberandletter(s string) string {
	numbers := "123456789"
	letters := "ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	punct := "?!#@&$"

	if !strings.ContainsAny(s, numbers) {
		s = "1" + s[1:]
		return ensurenumberandletter(s)
	}
	if !strings.ContainsAny(s, letters) {
		s = s[0:1] + "a" + s[2:]
		return ensurenumberandletter(s)
	}
	if !strings.ContainsAny(s, punct) {
		s = s[0:2] + "@" + s[3:]
		return ensurenumberandletter(s)
	}
	return s
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <site_address>\n", os.Args[0])
		os.Exit(1)
	}
	passwd := ""
	for passwd == "" {
		if passwd, err := gopass.GetPass(os.Args[1] + " password: "); err == nil {
			if passwd != "" {
				clipboard.WriteAll(generate(passwd, os.Args[1]))
				break
			}
		} else {
			panic(err)
		}
	}
}
