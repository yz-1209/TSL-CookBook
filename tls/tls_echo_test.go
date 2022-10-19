package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEchoServerTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverAddress := "localhost:34443"
	maxIdle := time.Second
	server := NewTLSServer(ctx, serverAddress, maxIdle, nil)
	done := make(chan struct{})

	go func() {
		err := server.ListenAndServerTLS("cert.pem", "key.pem")
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Error(err)
			return
		}

		done <- struct{}{}
	}()

	server.Ready()

	cert, err := os.ReadFile("cert.pem")
	require.Nil(t, err)

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(cert); !ok {
		t.Fatal("failed to append certificate to pool")
	}

	tlsConfig := &tls.Config{
		CurvePreferences: []tls.CurveID{tls.CurveP256},
		MinVersion:       tls.VersionTLS12,
		RootCAs:          certPool,
	}

	conn, err := tls.Dial("tcp", serverAddress, tlsConfig)
	assert.Nil(t, err)

	hello := []byte("hello")
	_, err = conn.Write(hello)
	require.Nil(t, err)

	b := make([]byte, 1024)
	n, err := conn.Read(b)
	require.Nil(t, err)
	require.Equal(t, hello, b[:n])

	time.Sleep(2 * maxIdle)
	_, err = conn.Read(b)
	require.Equal(t, io.EOF, err)

	err = conn.Close()
	require.Nil(t, err)

	cancel()
	<-done
}
