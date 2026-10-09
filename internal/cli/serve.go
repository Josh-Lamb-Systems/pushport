package cli

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/MunifTanjim/pushport/internal/api"
	"github.com/MunifTanjim/pushport/internal/app"
	"github.com/MunifTanjim/pushport/internal/config"
	"github.com/MunifTanjim/pushport/internal/crypto"
	"github.com/MunifTanjim/pushport/internal/db"
	"github.com/MunifTanjim/pushport/internal/instance"
	"github.com/MunifTanjim/pushport/internal/ratelimit"
	"github.com/MunifTanjim/pushport/internal/seal"
	"github.com/MunifTanjim/pushport/internal/settings"
	"github.com/MunifTanjim/pushport/internal/transport"
	"github.com/MunifTanjim/pushport/internal/turnstile"
	"github.com/MunifTanjim/pushport/internal/vapid"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the pushport server",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runServe()
		},
	}
}

func runServe() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	api.SetClientIPHeader(cfg.ClientIPHeader)

	database, err := db.Open(cfg.DatabaseURI)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer func() { _ = database.Close() }()

	keyring, err := crypto.NewKeyring(cfg.Secrets)
	if err != nil {
		return fmt.Errorf("secret keyring: %w", err)
	}
	apps := app.NewService(database, keyring)
	instances := instance.NewService(database.Queries, keyring)
	sealSvc := seal.NewService(apps)

	webpushPolicy, err := transport.NewEndpointPolicy(cfg.WebPushAllowedHosts)
	if err != nil {
		return fmt.Errorf("PUSHPORT_WEBPUSH_ALLOWED_HOSTS: %w", err)
	}

	// Safe to share one guarded client: only the registrant-controlled WebPush
	// URL is an SSRF risk; APNs/FCM/turnstile are public.
	httpClient, err := webpushPolicy.GuardClient(&http.Client{Timeout: 30 * time.Second})
	if err != nil {
		return fmt.Errorf("webpush ssrf guard: %w", err)
	}

	verifier := turnstile.New(httpClient)

	dispatcher := transport.NewDispatcher(apps, httpClient)
	dispatcher.SetLogger(slog.Default())

	resolver := ratelimit.NewResolver(database.Queries)
	gate := ratelimit.NewGate(resolver)
	registerLimiter := ratelimit.NewLimiter(nil)
	registerIPLimiter := ratelimit.NewLimiter(nil)
	subscribeLimiter := ratelimit.NewLimiter(nil)
	authFailLimiter := ratelimit.NewLimiter(nil)

	settingsReader := settings.NewReader(database.Queries)
	retrying := transport.NewRetryingSender(dispatcher, settingsReader)
	authThrottle := api.NewAuthThrottle(authFailLimiter, settingsReader)

	quotaStore := ratelimit.NewQuotaStore(gate.Quota(), database.Queries, nil)
	if err := quotaStore.Load(context.Background()); err != nil {
		log.Printf("quota: startup load failed: %v", err)
	}

	janitorDone := make(chan struct{})
	janitorStopped := make(chan struct{})
	go func() {
		defer close(janitorStopped)
		cleanup := time.NewTicker(5 * time.Minute)
		defer cleanup.Stop()
		flush := time.NewTicker(cfg.QuotaFlushInterval)
		defer flush.Stop()
		for {
			select {
			case <-janitorDone:
				// Final flush so in-flight counts survive a graceful shutdown.
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if err := quotaStore.Flush(ctx); err != nil {
					log.Printf("quota: final flush failed: %v", err)
				}
				cancel()
				return
			case <-cleanup.C:
				gate.Cleanup(30 * time.Minute)
				registerLimiter.Cleanup(30 * time.Minute)
				registerIPLimiter.Cleanup(30 * time.Minute)
				subscribeLimiter.Cleanup(30 * time.Minute)
				authFailLimiter.Cleanup(30 * time.Minute)
				if err := quotaStore.Cleanup(context.Background()); err != nil {
					log.Printf("quota: cleanup failed: %v", err)
				}
			case <-flush.C:
				if err := quotaStore.Flush(context.Background()); err != nil {
					log.Printf("quota: flush failed: %v", err)
				}
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// The install script lives with the docs; redirect so the short apex URL
	// (curl https://pushport.muniftanjim.dev/install.sh) works.
	mux.HandleFunc("GET /install.sh", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://docs.pushport.muniftanjim.dev/install.sh", http.StatusFound)
	})

	// Land on the docs site when the relay root is opened in a browser.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://docs.pushport.muniftanjim.dev", http.StatusFound)
	})

	admin := api.NewManagementHandler(apps, instances, database.Queries, cfg.AdminToken)
	admin.OnCredsChange(dispatcher.Invalidate)
	admin.OnRateConfigChange(func(string) { resolver.Flush() })
	admin.OnSettingsChange(settingsReader.Flush)
	admin.Routes(mux)

	device := api.NewDeviceHandler(sealSvc, apps, cfg.BaseURL, cfg.PushEndpoint.TTL, cfg.PushEndpoint.TTLMin, cfg.PushEndpoint.TTLMax)
	device.SetRateLimit(subscribeLimiter, resolver)
	device.SetWebPushPolicy(webpushPolicy)
	device.SetAllowVAPID(cfg.AllowVAPID)
	device.Routes(mux)

	registration := api.NewInstanceRegistrationHandler(instances, apps, registerLimiter, resolver, cfg.AdminToken, verifier)
	registration.SetIPRateLimit(registerIPLimiter)
	registration.Routes(mux)

	sendHandler := api.NewSendHandler(instances, sealSvc, retrying, cfg.MaxPayloadBytes)
	sendHandler.SetAdmitter(gate)
	if cfg.AllowVAPID {
		audience, err := vapid.Audience(cfg.BaseURL)
		if err != nil {
			return err
		}
		sendHandler.SetVAPIDAudience(audience)
	}
	sendHandler.Routes(mux)

	server := &http.Server{
		Addr:    cfg.Addr,
		Handler: api.WithCORS(cfg.CORSOrigins, api.WithRequestID(authThrottle.Wrap(mux))),
		// Bound slow-client (Slowloris) connections. WriteTimeout is intentionally
		// left unset: a push send runs its delivery + retry schedule synchronously
		// within the request (see SendHandler), so a fixed write deadline would
		// abort legitimate long sends; the read/idle deadlines defend the
		// slow-read DoS vectors on their own.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Bind synchronously so a failure returns here (running the deferred cleanup)
	// and "listening" is only logged once the socket is actually up.
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		close(janitorDone)
		<-janitorStopped
		return fmt.Errorf("listen on %s: %w", cfg.Addr, err)
	}
	log.Printf("pushport listening on %s", ln.Addr())

	serveErr := make(chan error, 1)
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()

	var exitErr error
	select {
	case sig := <-quit:
		log.Printf("received signal: %v, shutting down...", sig)
	case err := <-serveErr:
		log.Printf("serve error: %v", err)
		exitErr = err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}

	// Stop the janitor and wait for its final quota flush before the deferred
	// database.Close runs.
	close(janitorDone)
	<-janitorStopped
	return exitErr
}
