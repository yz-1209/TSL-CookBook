package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func CACertPool(caCertFn string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caCertFn)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCert); !ok {
		return nil, errors.New("failed to add certificate to pool")
	}

	return certPool, nil
}

func TestMutualTLSAuthentication(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPool, err := CACertPool("client.crt")
	assert.Nil(t, err)

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	assert.Nil(t, err)

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				Certificates:             []tls.Certificate{cert},
				ClientAuth:               tls.RequireAndVerifyClientCert,
				ClientCAs:                serverPool,
				CurvePreferences:         []tls.CurveID{tls.CurveP256},
				MinVersion:               tls.VersionTLS12,
				PreferServerCipherSuites: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					opts := x509.VerifyOptions{
						KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
						Roots:     serverPool,
					}

					ip := strings.Split(hello.Conn.RemoteAddr().String(), ":")[0]
					hostnames, err := net.LookupAddr(ip)
					assert.Nilf(t, err, "PTR lookup: %v", err)

					hostnames = append(hostnames, ip)
					for _, chain := range verifiedChains {
						opts.Intermediates = x509.NewCertPool()
						for _, cert := range chain[1:] {
							opts.Intermediates.AddCert(cert)
						}

						for _, hostname := range hostnames {
							opts.DNSName = hostname
							_, err = chain[0].Verify(opts)
							if err == nil {
								return nil
							}
						}
					}

					return errors.New("client authentication failed")
				},
			}, nil
		},
	}

	serverAddress := "localhost:44443"
	server := NewTLSServer(ctx, serverAddress, 0, serverConfig)
	done := make(chan struct{})

	go func() {
		err := server.ListenAndServerTLS("server.crt", "server.key")
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Error(err)
			return
		}

		done <- struct{}{}
	}()

	server.Ready()

	clientPool, err := CACertPool("server.crt")
	assert.Nil(t, err)

	clientCert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	assert.Nil(t, err)

	conn, err := tls.Dial("tcp", serverAddress, &tls.Config{
		Certificates:     []tls.Certificate{clientCert},
		CurvePreferences: []tls.CurveID{tls.CurveP256},
		MinVersion:       tls.VersionTLS12,
		RootCAs:          clientPool,
	})
	assert.Nil(t, err)

	hello := []byte("hello")
	_, err = conn.Write(hello)
	assert.Nil(t, err)

	b := make([]byte, 1024)
	n, err := conn.Read(b)
	assert.Nil(t, err)
	assert.Equal(t, hello, b[:n])

	err = conn.Close()
	assert.Nil(t, err)

	cancel()
	<-done
}
