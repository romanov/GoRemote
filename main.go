package main

import (
	"context"
	_ "embed"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

//go:embed web/index.html
var indexHTML []byte

//go:embed web/settings.html
var settingsHTML []byte

func main() {
	listenAddress := flag.String("listen", "0.0.0.0:8080", "HTTP listen address")
	commandTimeout := flag.Duration("timeout", 10*time.Minute, "maximum runtime for each command")
	allowlistPath := flag.String("allowlist-file", defaultAllowlistFile, "JSON file containing allowed client IP addresses")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *commandTimeout <= 0 {
		logger.Error("timeout must be greater than zero")
		os.Exit(2)
	}
	allowlist, err := newAllowlistStore(*allowlistPath)
	if err != nil {
		logger.Error("allowlist initialization failed", "error", err)
		os.Exit(2)
	}

	baseContext, cancelCommands := context.WithCancel(context.Background())
	defer cancelCommands()

	application := newApplicationWithAllowlist(newShellRunner(), *commandTimeout, logger, allowlist)
	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           application.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext: func(net.Listener) context.Context {
			return baseContext
		},
	}

	serveErrors := make(chan error, 1)
	go func() {
		logger.Info("command console listening", "address", *listenAddress, "timeout", commandTimeout.String())
		serveErrors <- server.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case sig := <-signals:
		logger.Info("shutdown requested", "signal", sig.String())
		cancelCommands()
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelShutdown()
		if err := server.Shutdown(shutdownContext); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			_ = server.Close()
		}
		if err := <-serveErrors; err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	case err := <-serveErrors:
		cancelCommands()
		if err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server failed", "error", err)
			os.Exit(1)
		}
	}
}
