package http

import (
	"bytes"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"io/ioutil"
	"io"
	"time"

	"github.com/gliderlabs/logspout/adapters/raw"
	"github.com/gliderlabs/logspout/router"
	"crypto/tls"
	"log"
	"fmt"
)

func init() {
	router.AdapterTransports.Register(new(httpTransport), "http")
	// convenience adapters around raw adapter
	router.AdapterFactories.Register(rawHTTPAdapter, "http")
}

func rawHTTPAdapter(route *router.Route) (router.LogAdapter, error) {
	route.Adapter = "raw+http"
	return raw.NewRawAdapter(route)
}

type httpTransport int
type httpConnection struct {
	client *http.Client
	url string
	user string
	pass string
}

func (c *httpConnection) Read(b [] byte) (n int, err error) {
	return 0, errors.New("Not implemented")
}

func (c *httpConnection) Write(b [] byte) (n int, err error) {
	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(c.user, c.pass)

	res, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}

	io.Copy(ioutil.Discard, res.Body)
	return len(b), res.Body.Close()
}

func (c *httpConnection) Close() error {
	return nil
}

func (c *httpConnection) LocalAddr() net.Addr {
	return nil
}

func (c *httpConnection) RemoteAddr() net.Addr {
	return nil
}

func (c *httpConnection) SetDeadline(t time.Time) error {
	return errors.New("Not implemented")
}

func (c *httpConnection) SetReadDeadline(t time.Time) error {
	return errors.New("Not implemented")
}

func (c *httpConnection) SetWriteDeadline(t time.Time) error {
	return errors.New("Not implemented")
}

func (t *httpTransport) Dial(addr string, options map[string]string) (net.Conn, error) {
	client := getClient(options)
	protocol, ok := options["http.proto"]
	if !ok {
		protocol = "https"
	}

	conn := &httpConnection{client, fmt.Sprintf("%s://%s/", protocol, addr), options["http.user"], options["http.pass"]}
	return conn, nil
}

func getClient(options map[string]string) *http.Client {
	tlsConfig, err := getTLSConfig(options)
	if err != nil {
		log.Fatalf("Error during TLS handshake: %s\n", err.Error())
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig, IdleConnTimeout: 1 * time.Hour}
	return &http.Client{Transport: transport}
}

func getTLSClientCerts(options map[string]string) ([]tls.Certificate, error) {
	certPath, certOk := options["http.cert"]
	keyPath, keyOk := options["http.key"]
	var certs []tls.Certificate

	if !certOk && !keyOk {
		return certs, nil
	} else if !certOk && !keyOk {
		fmt.Printf("Missing TLS client certificate or key")
		return nil, errors.New("TLS client configuration error")
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return certs, err
	}

	return []tls.Certificate{cert}, nil
}

func getRootCAs(options map[string]string) (*x509.CertPool, error) {
	caPath, ok := options["http.ca"]
	if !ok {
		return nil, nil
	}

	caPool := x509.NewCertPool()

	pem, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	ok = caPool.AppendCertsFromPEM(pem)
	if !ok {
		return nil, errors.New("Error parsing CA pem: " + caPath)
	}

	return caPool, nil
}

func getTLSConfig(options map[string]string) (*tls.Config, error) {
	certs, err := getTLSClientCerts(options)
	if err != nil {
		return nil, err
	}

	CAs, err := getRootCAs(options)
	if err != nil {
		return nil, err
	}

	conf := &tls.Config{Certificates: certs, RootCAs: CAs}
	return conf, nil
}
