package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"

	"github.com/quic-go/quic-go/http3"
)

func isCertExists() bool {
	fileCert, errCert := os.Open("cert.pem")
	fileCert.Close()
	if errors.Is(errCert, os.ErrNotExist) {
		return false
	}

	fileKey, errKey := os.Open("key.pem")
	fileKey.Close()
	if errors.Is(errKey, os.ErrNotExist) {
		return false
	}

	return true
}

func generateTLSCert() {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyOut, _ := os.Create("key.pem")
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certOut, _ := os.Create("cert.pem")
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func prepareProxyRequest(r *http.Request, targetHost string) *http.Request {
	request := r.Clone(r.Context())
	request.RemoteAddr = ""
	request.Proto = ""
	request.ProtoMajor = 0
	request.ProtoMinor = 0
	request.RequestURI = ""
	request.TLS = nil
	request.Close = false
	request.ContentLength = 0
	request.Header.Set("Host", targetHost)
	request.Header.Del("X-Forwarded-For")
	request.Header.Del("X-Forwarded-Proto")
	request.URL.Scheme = "https"
	request.URL.Host = targetHost
	request.Host = targetHost
	return request
}

func writeError(w http.ResponseWriter, err error) {
	w.WriteHeader(500)
	_, errWrite := w.Write([]byte(err.Error()))
	if errWrite != nil {
		log.Printf("Error: %v", errWrite)
	}
}

func mkHandler() http.HandlerFunc {

	http3Client := http.Client{
		Transport: &http3.RoundTripper{},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		request := prepareProxyRequest(r, r.TLS.ServerName)

		response, err := http3Client.Do(request)
		if err != nil {
			log.Println(err)
			writeError(w, err)
			return
		}

		log.Println(
			response.StatusCode,
			response.ContentLength,
			response.Proto)

		// ignore error (nothing to do if connection to server close)
		defer func() {
			if err = response.Body.Close(); err != nil {
				log.Println(err)
			}
		}()

		// copy response headers
		for header, values := range response.Header {
			for _, value := range values {
				w.Header().Add(header, value)
			}
		}

		// can error only if connection is closed on either end. no point of printing such error.
		if _, err = io.Copy(w, response.Body); err != nil {
			log.Println(err)
			writeError(w, err)
			return
		}

		w.WriteHeader(response.StatusCode)
	}
}

func main() {
	if !isCertExists() {
		generateTLSCert()
	}
	http3.ListenAndServe("0.0.0.0:8080", "cert.pem", "key.pem", mkHandler())
}
