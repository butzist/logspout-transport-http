package http

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"io/ioutil"
	"io"
	"time"

	"github.com/gliderlabs/logspout/adapters/raw"
	"github.com/gliderlabs/logspout/router"
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
	client := &http.Client{ Transport: &http.Transport{ IdleConnTimeout: 1 * time.Hour }}
	conn := &httpConnection { client, "https://" + addr + "/", options["http.user"], options["http.pass"] }
	return conn, nil
}
