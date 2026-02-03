package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
)

func init() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger.With("appName", "pii-leak-detector"))
}

func main() {
	ctx := context.Background()
	logger := slog.Default()

	go http.ListenAndServe(":6060", nil)

	sources := []Source{
		{
			SourceType: FileSource,
			FilePath:   "./inputs/logs_clean.txt",
		},
		{
			SourceType: FileSource,
			FilePath:   "./inputs/logs_with_pii.txt",
		},
	}

	res := analyzeSources(ctx, logger, sources...)
	if res.Err != nil {
		slog.Error("error happened during source analyze", "err", res.Err)
	}

	b, _ := json.MarshalIndent(res, "", "\t")
	fmt.Println("Output:", "result", string(b))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
}
