package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	piileakdetector "github/martinmaurice/pii-leak-detector"
	"log"
	"log/slog"
	_ "net/http/pprof"
	"os"
	"strings"
)

var (
	sourceFilePaths string
	sourceContent   string
)

func init() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger.With("appName", "pii-leak-detector"))

	flag.StringVar(
		&sourceFilePaths,
		"files",
		"",
		"enter the paths of the files you want to analyze. ie: -files file.txt,file2.txt",
	)

	flag.StringVar(
		&sourceContent,
		"content",
		"",
		"enter the content you want to analyze. ie: -content='This line contains one email leak: john@doe.com\n'",
	)
}

func main() {
	flag.Parse()

	ctx := context.Background()
	logger := slog.Default()

	sources := getSources()
	if len(sources) == 0 {
		log.Fatalf("You must specify at least one source to analyze")
		os.Exit(1)
	}

	fmt.Printf("sources: %v", sources)

	analyzer := piileakdetector.NewAnalyzer(logger, sources)
	result := analyzer.Run(ctx)
	if result.Err != nil {
		slog.Error("error happened during source analyze", "err", result.Err)
	}

	renderAnalysisResult(result)
}

func getSources() (sources []piileakdetector.Source) {
	if sourceFilePaths != "" {
		paths := strings.Split(sourceFilePaths, ",")
		for _, path := range paths {
			sources = append(sources, piileakdetector.Source{
				SourceType: piileakdetector.FileSource,
				FilePath:   strings.TrimSpace(path),
			})
		}
	}

	if sourceContent != "" {
		sources = append(sources, piileakdetector.Source{
			SourceType: piileakdetector.StringSource,
			Content:    strings.Replace(sourceContent, "\\n", "\n", -1),
		})
	}

	return
}

func renderAnalysisResult(result piileakdetector.AnalysisResult) {
	var data [][]any

	if result.NumberOfSourcesWithPIILeaks == 0 {
		fmt.Printf("\n\n✅  No Leaks Found! ✅  \n\n")
		return
	} else {
		fmt.Printf("\n\n❌  Leaks found in %d file(s) ❌ ", result.NumberOfSourcesWithPIILeaks)
	}

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
				data = append(data, [][]any{{
					sar.Source,
					sar.HighestThreatLevel,
					ld.LineNumber,
					d.Leak,
					d.DetectionCategory,
					d.ThreatLevel,
				}}...)
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
