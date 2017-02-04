// Copyright (C) 2017 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"strings"
	"sync/atomic"

	"github.com/fullsailor/pkcs7"
)

var verbose = flag.Bool("v", false, "Enable verbose output")

var numErrors uint32

func extractCertsFromPKCS7(data []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	certs := make([]*x509.Certificate, 0, len(p7.Certificates))

	for _, cert := range p7.Certificates {
		certs = append(certs, cert)
	}

	return certs, nil
}

func discardReader(r io.Reader) error {
	_, err := io.Copy(ioutil.Discard, r)
	return err
}

func processPart(contentType string, cte string, body io.Reader, certsOut chan<- *x509.Certificate) error {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		log.Printf("Ignoring part of email because of bad MIME type: %s\n", err)
		atomic.AddUint32(&numErrors, 1)
		return discardReader(body)
	}
	if cte == "quoted-printable" {
		body = quotedprintable.NewReader(body)
	} else if cte == "base64" {
		body = base64.NewDecoder(base64.StdEncoding, body)
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		return processMultipart(body, params["boundary"], certsOut)
	} else if mediaType == "application/pkcs7-signature" {
		data, err := ioutil.ReadAll(body)
		if err != nil {
			return err
		}
		certs, err := extractCertsFromPKCS7(data)
		if err != nil {
			log.Printf("Ignoring part of email because could not extract PKCS7 certs: %s\n", err)
			atomic.AddUint32(&numErrors, 1)
		} else {
			for _, cert := range certs {
				certsOut <- cert
			}
		}
		return nil
	} else {
		return discardReader(body)
	}
}

func processMultipart(r io.Reader, boundary string, certsOut chan<- *x509.Certificate) error {
	reader := multipart.NewReader(r, boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		err = processPart(part.Header.Get("Content-Type"), part.Header.Get("Content-Transfer-Encoding"), part, certsOut)
		if err != nil {
			return err
		}
	}
	return nil
}

func processEmail(r io.Reader, certsOut chan<- *x509.Certificate) error {
	mesg, err := mail.ReadMessage(r)
	if err != nil {
		return err
	}
	return processPart(mesg.Header.Get("Content-Type"), mesg.Header.Get("Content-Transfer-Encoding"), mesg.Body, certsOut)
}

func main() {
	flag.Parse()

	log.SetPrefix("email2certs: ")

	certsChan := make(chan *x509.Certificate, 16)

	go func() {
		err := processEmail(os.Stdin, certsChan)
		if err != nil {
			log.Fatalf("Error parsing email from stdin: %s", err)
		}
		close(certsChan)
	}()

	numCerts := 0
	for cert := range certsChan {
		numCerts++
		if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			log.Fatalf("Error writing to stdout: %s", err)
		}
	}

	if *verbose {
		log.Printf("%d certificates extracted", numCerts)
	}
	if numErrors > 0 {
		log.Printf("%d parse errors", numErrors)
		os.Exit(3)
	}
}
