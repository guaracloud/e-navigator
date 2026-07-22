// Command go-https-proof provides a deterministic TLS server and bounded load
// client for homelab-only E-Navigator plaintext-capture validation.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxRequests    = 100_000
	maxConcurrency = 128
	maxBodyBytes   = 4096
)

type options struct {
	mode         string
	listen       string
	url          string
	requests     int
	concurrency  int
	startupDelay time.Duration
}

type proofResponse struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	RequestID string `json:"request_id"`
	Server    string `json:"server"`
}

type clientSummary struct {
	Schema                 string  `json:"schema"`
	GoVersion              string  `json:"go_version"`
	Requests               int     `json:"requests"`
	Concurrency            int     `json:"concurrency"`
	Succeeded              uint64  `json:"succeeded"`
	Failed                 uint64  `json:"failed"`
	ElapsedSeconds         float64 `json:"elapsed_seconds"`
	ThroughputRequestsSecs float64 `json:"throughput_requests_per_second"`
}

func main() {
	config := parseFlags()
	var err error
	switch config.mode {
	case "server":
		err = runServer(config)
	case "client":
		err = runClient(config)
	default:
		err = fmt.Errorf("unsupported mode %q", config.mode)
	}
	if err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func parseFlags() options {
	var config options
	flag.StringVar(&config.mode, "mode", "server", "server or client")
	flag.StringVar(&config.listen, "listen", ":8443", "TLS server listen address")
	flag.StringVar(&config.url, "url", "https://127.0.0.1:8443", "client base URL")
	flag.IntVar(&config.requests, "requests", 1000, "bounded request count")
	flag.IntVar(&config.concurrency, "concurrency", 8, "bounded client workers")
	flag.DurationVar(&config.startupDelay, "startup-delay", 20*time.Second, "delay after readiness")
	flag.Parse()
	return config
}

func runServer(config options) error {
	certificate, err := ephemeralCertificate()
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	var served atomic.Uint64
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "ok\n")
	})
	mux.HandleFunc("/proof", func(writer http.ResponseWriter, request *http.Request) {
		served.Add(1)
		response := proofResponse{
			Method:    request.Method,
			Path:      request.URL.Path,
			RequestID: request.URL.Query().Get("request_id"),
			Server:    runtime.Version(),
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-E-Navigator-Proof", "go-crypto-tls")
		if err := json.NewEncoder(writer).Encode(response); err != nil {
			log.Printf("encode response: %v", err)
		}
	})
	mux.HandleFunc("/stats", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"schema":     "e-navigator.go-tls-server.v1",
			"go_version": runtime.Version(),
			"served":     served.Load(),
		})
	})

	listener, err := tls.Listen("tcp", config.listen, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()

	log.Printf("ready schema=e-navigator.go-tls-server.v1 listen=%s go_version=%s", config.listen, runtime.Version())
	err = server.Serve(listener)
	if !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	<-done
	log.Printf("stopped served=%d", served.Load())
	return nil
}

func runClient(config options) error {
	if config.requests < 1 || config.requests > maxRequests {
		return fmt.Errorf("requests must be between 1 and %d", maxRequests)
	}
	if config.concurrency < 1 || config.concurrency > maxConcurrency {
		return fmt.Errorf("concurrency must be between 1 and %d", maxConcurrency)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Homelab fixture uses an ephemeral self-signed certificate.
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		},
		MaxIdleConns:        config.concurrency,
		MaxIdleConnsPerHost: config.concurrency,
		IdleConnTimeout:     30 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	if err := waitReady(client, config.url); err != nil {
		return err
	}
	if config.startupDelay > 0 {
		log.Printf("capture discovery delay=%s", config.startupDelay)
		time.Sleep(config.startupDelay)
	}

	started := time.Now()
	jobs := make(chan int)
	var succeeded atomic.Uint64
	var failed atomic.Uint64
	var firstError atomic.Pointer[string]
	var workers sync.WaitGroup
	for worker := 0; worker < config.concurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for requestNumber := range jobs {
				requestID := "go-tls-proof-" + strconv.Itoa(requestNumber)
				if err := executeProofRequest(client, config.url, requestID); err != nil {
					failed.Add(1)
					message := err.Error()
					firstError.CompareAndSwap(nil, &message)
					continue
				}
				succeeded.Add(1)
			}
		}()
	}
	for requestNumber := 0; requestNumber < config.requests; requestNumber++ {
		jobs <- requestNumber
	}
	close(jobs)
	workers.Wait()
	elapsed := time.Since(started)
	summary := clientSummary{
		Schema:                 "e-navigator.go-tls-client.v1",
		GoVersion:              runtime.Version(),
		Requests:               config.requests,
		Concurrency:            config.concurrency,
		Succeeded:              succeeded.Load(),
		Failed:                 failed.Load(),
		ElapsedSeconds:         elapsed.Seconds(),
		ThroughputRequestsSecs: float64(succeeded.Load()) / elapsed.Seconds(),
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("encode summary: %w", err)
	}
	fmt.Println(string(encoded))
	if summary.Failed != 0 {
		if message := firstError.Load(); message != nil {
			return fmt.Errorf("%d requests failed; first error: %s", summary.Failed, *message)
		}
		return fmt.Errorf("%d requests failed", summary.Failed)
	}
	return nil
}

func waitReady(client *http.Client, baseURL string) error {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(baseURL + "/healthz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("TLS service did not become ready within 90 seconds")
}

func executeProofRequest(client *http.Client, baseURL, requestID string) error {
	request, err := http.NewRequest(http.MethodGet, baseURL+"/proof?request_id="+requestID, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("X-E-Navigator-Proof", "go-crypto-tls")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	var decoded proofResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if decoded.Method != http.MethodGet || decoded.Path != "/proof" || decoded.RequestID != requestID {
		return fmt.Errorf("response mismatch for %s", requestID)
	}
	return nil
}

func ephemeralCertificate() (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "e-navigator-go-tls-proof"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "go-tls"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
