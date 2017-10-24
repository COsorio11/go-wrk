package loader

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"

	"fmt"

	"time"

	"github.com/tsliwowicz/go-wrk/util"
	"golang.org/x/net/http2"
)

func client(disableCompression bool, disableKeepAlive bool, timeoutms int, allowRedirects bool, clientCert, clientKey, caCert string, usehttp2 bool, insecure bool) (*http.Client, error) {

	var tlsConfig *tls.Config = nil

	client := &http.Client{}
	//overriding the default parameters
	client.Transport = &http.Transport{
		DisableCompression:    disableCompression,
		DisableKeepAlives:     disableKeepAlive,
		ResponseHeaderTimeout: time.Millisecond * time.Duration(timeoutms),
	}

	if !allowRedirects {
		//returning an error when trying to redirect. This prevents the redirection from happening.
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return util.NewRedirectError("redirection not allowed")
		}
	}

	if insecure {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	} else {
		if clientCert == "" && clientKey == "" && caCert == "" {
			return client, nil
		}

		if clientCert == "" {
			return nil, fmt.Errorf("client certificate can't be empty")
		}

		if clientKey == "" {
			return nil, fmt.Errorf("client key can't be empty")
		}
		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("Unable to load cert tried to load %v and %v but got %v", clientCert, clientKey, err)
		}

		// Load our CA certificate
		clientCACert, err := ioutil.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("Unable to open cert %v", err)
		}

		clientCertPool := x509.NewCertPool()
		clientCertPool.AppendCertsFromPEM(clientCACert)

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      clientCertPool,
		}

		tlsConfig.BuildNameToCertificate()
	}

	transporter := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if usehttp2 {
		http2.ConfigureTransport(transporter)
	}

	client.Transport = transporter
	return client, nil
}
