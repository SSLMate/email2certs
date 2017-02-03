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
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fullsailor/pkcs7"
)

var verbose = flag.Bool("v", false, "Enable verbose output")

var parseErrors uint32
var submitErrors uint32

var ctlogs = []string{
	"ct.googleapis.com/pilot",
	"ct.googleapis.com/rocketeer",
}

type SubmitMessage struct {
	Chain [][]byte `json:"chain"`
}

type Chain []*x509.Certificate

func (c Chain) GetRawCerts() [][]byte {
	rawCerts := make([][]byte, len(c))
	for i := range c {
		rawCerts[i] = c[i].Raw
	}
	return rawCerts
}

func findCertificate(certs []*x509.Certificate, subject []byte) *x509.Certificate {
	for _, cert := range certs {
		if bytes.Equal(cert.RawSubject, subject) {
			return cert
		}
	}
	return nil
}

func buildChain(cert *x509.Certificate, certs []*x509.Certificate) []*x509.Certificate {
	chain := make([]*x509.Certificate, 0)
	for len(chain) < 16 && cert != nil && !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		chain = append(chain, cert)
		cert = findCertificate(certs, cert.RawIssuer)
	}
	return chain
}

func extractChainsFromPKCS7(data []byte) ([]Chain, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	chains := make([]Chain, 0, len(p7.Certificates))

	for _, cert := range p7.Certificates {
		chains = append(chains, buildChain(cert, p7.Certificates))
	}

	return chains, nil
}

func discardReader(r io.Reader) error {
	_, err := io.Copy(ioutil.Discard, r)
	return err
}

func processPart(contentType string, cte string, body io.Reader, chainsOut chan<- Chain) error {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		log.Printf("Ignoring part of email because of bad MIME type: %s\n", err)
		atomic.AddUint32(&parseErrors, 1)
		return discardReader(body)
	}
	if cte == "quoted-printable" {
		body = quotedprintable.NewReader(body)
	} else if cte == "base64" {
		body = base64.NewDecoder(base64.StdEncoding, body)
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		return processMultipart(body, params["boundary"], chainsOut)
	} else if mediaType == "application/pkcs7-signature" {
		data, err := ioutil.ReadAll(body)
		if err != nil {
			return err
		}
		chains, err := extractChainsFromPKCS7(data)
		if err != nil {
			log.Printf("Ignoring part of email because could not extract PKCS7 chains: %s\n", err)
			atomic.AddUint32(&parseErrors, 1)
		} else {
			for _, chain := range chains {
				chainsOut <- chain
			}
		}
		return nil
	} else {
		return discardReader(body)
	}
}

func processMultipart(r io.Reader, boundary string, chains chan<- Chain) error {
	reader := multipart.NewReader(r, boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		err = processPart(part.Header.Get("Content-Type"), part.Header.Get("Content-Transfer-Encoding"), part, chains)
		if err != nil {
			return err
		}
	}
	return nil
}

func processEmail(r io.Reader, chains chan<- Chain) error {
	mesg, err := mail.ReadMessage(r)
	if err != nil {
		return err
	}
	return processPart(mesg.Header.Get("Content-Type"), mesg.Header.Get("Content-Transfer-Encoding"), mesg.Body, chains)
}

func submitToLog(server string, mesg *SubmitMessage) ([]byte, error) {
	mesgReader, mesgWriter := io.Pipe()
	go func() {
		json.NewEncoder(mesgWriter).Encode(mesg)
		mesgWriter.Close()
	}()
	resp, err := http.Post("https://"+server+"/ct/v1/add-chain", "application/json", mesgReader)
	if err != nil {
		return nil, fmt.Errorf("HTTP error %s", err)
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("CT Server Error: %s", string(respBody))
	}
	return respBody, nil
}

func submitChain(chain Chain) {
	if len(chain) == 0 {
		return
	}
	cn := chain[0].Subject.CommonName
	mesg := SubmitMessage{Chain: chain.GetRawCerts()}

	wg := sync.WaitGroup{}
	for _, server := range ctlogs {
		wg.Add(1)
		go func(server string) {
			respBody, err := submitToLog(server, &mesg)
			if err != nil {
				log.Printf("%s: %s: %s", cn, server, err)
				atomic.AddUint32(&submitErrors, 1)
			} else {
				if *verbose {
					log.Printf("%s: %s: %s", cn, server, string(respBody))
				}
			}
			wg.Done()
		}(server)
	}
	wg.Wait()
}

func main() {
	flag.Parse()

	log.SetPrefix("smime2ct: ")

	chainsChan := make(chan Chain, 16)

	go func() {
		err := processEmail(os.Stdin, chainsChan)
		if err != nil {
			log.Fatalf("Error parsing email from stdin: %s", err)
		}
		close(chainsChan)
	}()

	wg := sync.WaitGroup{}
	for chain := range chainsChan {
		wg.Add(1)
		go func(chain Chain) {
			submitChain(chain)
			wg.Done()
		}(chain)
	}
	wg.Wait()

	exitStatus := 0
	if parseErrors > 0 {
		log.Printf("%d errors when parsing email", parseErrors)
		exitStatus |= 4
	}
	if submitErrors > 0 {
		log.Printf("%d errors when submitting to CT logs", submitErrors)
		exitStatus |= 8
	}
	os.Exit(exitStatus)
}
