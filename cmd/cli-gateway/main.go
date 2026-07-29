package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	mcpadapter "github.com/wyh0626/cli-gateway/internal/adapter/mcp"
	"github.com/wyh0626/cli-gateway/internal/audit"
	"github.com/wyh0626/cli-gateway/internal/auth"
	"github.com/wyh0626/cli-gateway/internal/credential"
	"github.com/wyh0626/cli-gateway/internal/identity"
	"github.com/wyh0626/cli-gateway/internal/invoke"
	"github.com/wyh0626/cli-gateway/internal/limiter"
	"github.com/wyh0626/cli-gateway/internal/manifest"
	"github.com/wyh0626/cli-gateway/internal/observability"
	runtimecfg "github.com/wyh0626/cli-gateway/internal/runtime"
	"github.com/wyh0626/cli-gateway/internal/server"
)

func main() {
	manifestPath := flag.String("manifest", "manifest.yaml", "path to the cli-gateway manifest")
	downloadDir := flag.String("downloads", "/usr/local/share/cli-gateway/downloads", "directory containing downloadable CLI artifacts")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	snapshot, err := manifest.LoadFile(*manifestPath)
	if err != nil {
		logger.Error("load initial manifest", "error", err)
		os.Exit(1)
	}
	startupContext, cancelStartup := context.WithTimeout(context.Background(), 10*time.Second)
	jwksURL := snapshot.AuthTrustedJWKS
	if snapshot.AuthMode == "oidc" {
		metadata, discoveryErr := auth.DiscoverIssuerWithTLS(startupContext, snapshot.AuthIssuer, snapshot.Environment != "production", snapshot.AuthTLS)
		if discoveryErr != nil {
			cancelStartup()
			logger.Error("discover OIDC issuer", "error", discoveryErr)
			os.Exit(1)
		}
		jwksURL = metadata.JWKSURI
	}
	verifier, err := auth.NewRemoteJWTVerifierWithTLS(startupContext, jwksURL, snapshot.AuthIssuer, snapshot.AuthAudience, snapshot.Environment != "production", snapshot.AuthTLS)
	cancelStartup()
	if err != nil {
		logger.Error("initialize JWT verifier", "error", err)
		os.Exit(1)
	}
	if err := verifier.ConfigureIdentityClaims(snapshot.AuthIdentityClaims); err != nil {
		logger.Error("configure downstream identity claims", "error", err)
		os.Exit(1)
	}
	signer, err := identity.NewRotatingSigner(snapshot.IdentityKeyFile, snapshot.IdentityPreviousKeyFiles, snapshot.Environment)
	if err != nil {
		logger.Error("initialize identity signer", "error", err)
		os.Exit(1)
	}
	if snapshot.Environment != "production" && snapshot.IdentityKeyFile == "" {
		logger.Warn("using an ephemeral development identity signing key", "kid", signer.KeyID())
	}
	cacheKey := make([]byte, 32)
	if _, err := rand.Read(cacheKey); err != nil {
		logger.Error("initialize credential cache key", "error", err)
		os.Exit(1)
	}
	secrets := credential.EnvironmentSecrets{}
	var authorizationStore credential.AuthorizationTokenStore
	if snapshot.OAuthTokenStoreFile != "" {
		encryptionSecret, resolveErr := secrets.Resolve(snapshot.OAuthEncryptionKeyRef)
		if resolveErr != nil {
			logger.Error("resolve downstream OAuth token-store key", "error", resolveErr)
			os.Exit(1)
		}
		authorizationStore, err = credential.NewEncryptedFileAuthorizationTokenStore(snapshot.OAuthTokenStoreFile, encryptionSecret)
	} else {
		authorizationStore, err = credential.NewMemoryAuthorizationTokenStore(cacheKey)
	}
	if err != nil {
		logger.Error("initialize downstream OAuth token store", "error", err)
		os.Exit(1)
	}
	authorizationBroker, err := credential.NewAuthorizationCodeBroker(authorizationStore, secrets, snapshot.OAuthStateTTL)
	if err != nil {
		logger.Error("initialize downstream OAuth broker", "error", err)
		os.Exit(1)
	}
	metrics := &observability.Registry{}
	runtimeManager, err := runtimecfg.NewManager(*manifestPath, 10*time.Second, func(generationSnapshot *manifest.Snapshot) (runtimecfg.Components, error) {
		credentialManager, buildErr := credential.NewManagerWithAuthorizationCode(generationSnapshot, signer, cacheKey, secrets, authorizationBroker, metrics)
		if buildErr != nil {
			return runtimecfg.Components{}, buildErr
		}
		admissionManager, buildErr := limiter.NewManager(generationSnapshot)
		if buildErr != nil {
			return runtimecfg.Components{}, buildErr
		}
		auditDispatcher, buildErr := audit.Build(generationSnapshot.AuditSinks, logger, os.Stdout, metrics)
		if buildErr != nil {
			return runtimecfg.Components{}, buildErr
		}
		invocationService := invoke.NewServiceWithAdmission(credentialManager, admissionManager)
		if buildErr := invocationService.Preflight(generationSnapshot); buildErr != nil {
			return runtimecfg.Components{}, buildErr
		}
		return runtimecfg.Components{
			Invoker: invocationService,
			Audit:   auditDispatcher,
			Close: func() error {
				invocationService.CloseIdleConnections()
				closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return auditDispatcher.Close(closeContext)
			},
		}, nil
	})
	if err != nil {
		logger.Error("initialize runtime", "error", err)
		os.Exit(1)
	}
	metrics.SetGeneration(runtimeManager.Current().ID)
	runtimeManager.Subscribe(func(_, next *runtimecfg.Generation) {
		if next != nil {
			metrics.SetGeneration(next.ID)
			metrics.RecordReload(true)
		}
	})
	resourceMetadataURL := strings.TrimSuffix(snapshot.PublicURL, "/") + "/.well-known/oauth-protected-resource/mcp"
	mcpHandler, err := mcpadapter.New(runtimeManager, verifier, resourceMetadataURL, logger, metrics)
	if err != nil {
		logger.Error("initialize MCP adapter", "error", err)
		os.Exit(1)
	}

	watchContext, stopWatching := context.WithCancel(context.Background())
	defer stopWatching()
	verifier.Start(watchContext)
	go func() {
		if err := runtimeManager.Watch(watchContext, func(reloadErr error) {
			metrics.RecordReload(false)
			logger.Error("manifest reload rejected", "error", reloadErr)
		}); err != nil {
			logger.Error("manifest watcher stopped", "error", err)
		}
	}()

	httpServer := &http.Server{
		Addr: snapshot.Listen,
		Handler: server.NewHandler(nil, server.Dependencies{
			Verifier:        verifier,
			Signer:          signer,
			Runtime:         runtimeManager,
			Metrics:         metrics,
			MCP:             mcpHandler,
			DownstreamOAuth: authorizationBroker,
			DownloadDir:     *downloadDir,
			PublicURL:       snapshot.PublicURL,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveErrors := make(chan error, 1)
	go func() {
		logger.Info("cli-gateway listening", "address", snapshot.Listen, "manifest_etag", snapshot.ETag)
		if serveErr := httpServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serveErrors <- serveErr
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	for {
		select {
		case serveErr := <-serveErrors:
			logger.Error("HTTP server stopped", "error", serveErr)
			stopWatching()
			os.Exit(1)
		case received := <-signals:
			if received == syscall.SIGHUP {
				if reloadErr := runtimeManager.Reload(); reloadErr != nil {
					metrics.RecordReload(false)
					logger.Error("SIGHUP manifest reload rejected", "error", reloadErr)
				} else {
					current := runtimeManager.Current()
					logger.Info("manifest reloaded", "manifest_etag", current.Snapshot.ETag, "runtime_generation", current.ID)
				}
				continue
			}
			stopWatching()
			shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if shutdownErr := httpServer.Shutdown(shutdownContext); shutdownErr != nil {
				logger.Error("graceful shutdown failed", "error", shutdownErr)
			}
			mcpHandler.Close()
			if runtimeErr := runtimeManager.Close(shutdownContext); runtimeErr != nil {
				logger.Error("runtime shutdown failed", "error", runtimeErr)
			}
			cancel()
			logger.Info("cli-gateway stopped", "signal", received.String())
			return
		}
	}
}
