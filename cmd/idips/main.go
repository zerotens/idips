package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"idips/internal/app"
	"idips/internal/logstream"
)

func main() {
	dataDir := flag.String("data", envOr("IDIPS_DATA", "data"), "data directory for SQLite, keys and wireproxy configs")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(app.Version)
		return
	}

	level := new(slog.LevelVar)
	switch strings.ToLower(envOr("IDIPS_LOG_LEVEL", "info")) {
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}
	logs := logstream.New(500)
	logger := slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, logs), &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, *dataDir, logger, level, logs)
	if err != nil {
		logger.Error("initialization failed", "error", err)
		os.Exit(1)
	}
	logger.Info("IDIPS starting", "version", app.Version, "data", a.DataDir, "admin", a.AdminURL())
	if err := a.Run(ctx); err != nil {
		logger.Error("service stopped with error", "error", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
