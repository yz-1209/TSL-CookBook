package tls

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
)

func TestClientTLS(t *testing.T) {
	// Here, the httptest.NewTLSServer function handles the HTTPS server's TLS configuration details, including
	// the creation of a new certificate. No trusted authority signed this certificate, so no discerning HTTPS client
	// would trust it.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			u := "https://" + r.Host + r.RequestURI
			http.Redirect(w, r, u, http.StatusMovedPermanently)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Using a preconfigured client
	resp, err := ts.Client().Get(ts.URL)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	tp := &http.Transport{
		TLSClientConfig: &tls.Config{
			// It's good practice to restrict your client's curve perference to the P-256 curve.
			// An elliptic curve is a plane curve in which all points along the curve satisfy the same polynomial
			// equation. Whereas first-generation cryptography like RSA uses large prime numbers to derive keys, elliptic
			// curve cryptography uses points along an elliptic curve for key generation.
			CurvePreferences: []tls.CurveID{tls.CurveP256},

			// Negotiate a minimum of TLS 1.2
			MinVersion: tls.VersionTLS12,
		},
	}

	err = http2.ConfigureTransport(tp)
	assert.Nil(t, err)

	// Override the default TLS configuration
	client2 := &http.Client{Transport: tp}

	// Your client uses the operation system's trusted certificate store because you don't explicity tell it which
	// certificate to trust.
	_, err = client2.Get(ts.URL)
	assert.Contains(t, err.Error(), "certificate is not trusted")

	// Skip verification of the server's certificate
	tp.TLSClientConfig.InsecureSkipVerify = true

	resp, err = client2.Get(ts.URL)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestClientTLSGoogle(t *testing.T) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 30 * time.Second},
		"tcp",
		"www.google.com:443",
		&tls.Config{
			CurvePreferences: []tls.CurveID{tls.CurveP256},
			MinVersion:       tls.VersionTLS12,
		},
	)
	assert.Nil(t, err)

	state := conn.ConnectionState()
	t.Logf("TLS %d", state.Version)
	t.Log(tls.CipherSuiteName(state.CipherSuite))
	t.Log(state.VerifiedChains[0][0].Issuer.Organization[0])

	_ = conn.Close()
}
