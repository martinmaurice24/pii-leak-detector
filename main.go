package main

import (
	"context"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
)

func init() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	slog.SetDefault(logger.With("appName", "pii-leak-detector"))
}

func renderAnalyzeResult(result AnalysisResult) {
	var data [][]any

	fmt.Printf(
		"\n\nNumber of sources analyzed: %d\nNumber of sources with PII leaks: %d\nHighest Threat Level Found: %s\nSome Errors Caught: %v\nProcess Duration In Milliseconds: %s\n\n",
		result.NumberOfAnalyzedSources,
		result.NumberOfSourcesWithPIILeaks,
		result.HighestThreatLevel,
		result.Err != nil,
		result.TotalAnalysisDuration,
	)

	for _, sar := range result.SourceAnalysisResults {
		for _, ld := range sar.ByLineDetections {
			for _, d := range ld.Detections {
				data = append(data, [][]any{{sar.Source, sar.HighestThreatLevel, ld.LineNumber, d.Leak, d.DetectionCategory, d.ThreatLevel}}...)
			}
		}
	}

	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Settings: tw.Settings{Separators: tw.Separators{BetweenRows: tw.On}},
		})),
		tablewriter.WithConfig(tablewriter.Config{
			Header: tw.CellConfig{Alignment: tw.CellAlignment{Global: tw.AlignCenter}},
			Row: tw.CellConfig{
				Merging:   tw.CellMerging{Mode: tw.MergeHierarchical},
				Alignment: tw.CellAlignment{Global: tw.AlignLeft},
			},
		}),
	)
	table.Header([]string{"Source", "Highest Threat Level", "Line Number", "Leak", "Category", "Threat Level"})
	table.Bulk(data)
	table.Render()
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

	analyzer := NewAnalyzer(logger, sources)
	res := analyzer.Run(ctx)
	if res.Err != nil {
		slog.Error("error happened during source analyze", "err", res.Err)
	}

	renderAnalyzeResult(res)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
}
