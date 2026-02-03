package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

type LineDetections struct {
	LineNumber         int
	Detections         []Detection
	HighestThreatLevel ThreatLevel
}

type SourceAnalyzeResult struct {
	// the source of data that was analyzed (i.e: fileName)
	Source               Source
	NumberOfLinesScanned int
	ByLineDetections     []LineDetections
	HighestThreatLevel   ThreatLevel
	AnalyzeTime          time.Duration
	Err                  error
}

type AnalyzeResult struct {
	NumberOfAnalyzedSources     int
	SourceAnalyzeResults        []SourceAnalyzeResult
	NumberOfSourcesWithPIILeaks int
	HighestThreatLevel          ThreatLevel
	TotalAnalyzeDuration        time.Duration
	DetectionsRaw               string
	Err                         error
}

var (
	ReadSourceErr = errors.New("failed to read the source")
)

type contentRow struct {
	Err        error
	Line       string
	LineNumber int
}

func readSourceContentLines(ctx context.Context, logger *slog.Logger, s Source) <-chan contentRow {
	logger.Debug("reading source content lines", "source", s)
	rowsStream := make(chan contentRow)
	go func() {
		defer close(rowsStream)
		sourceContent, err := s.Read(ctx)
		if err != nil {
			logger.Error(ReadSourceErr.Error(), "s", s, "err", err)
			rowsStream <- contentRow{
				Err: errors.Join(ReadSourceErr, err),
			}
			return
		}

		logger.Debug("Read the source content successfully", "content", string(sourceContent))

		r := bufio.NewReader(bytes.NewReader(sourceContent))
		lineNumber := 1
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line, err := r.ReadBytes('\n')
			if err == io.EOF {
				logger.Debug("End of file")
				break
			} else if err != nil {
				logger.Error(err.Error(), "line", string(line))
			} else {
				logger.Debug("Extracting line", "nb", lineNumber, "line", string(line))
			}

			rowsStream <- contentRow{
				Err:        err,
				Line:       string(line),
				LineNumber: lineNumber,
			}

			lineNumber++
		}
		logger.Debug("Exiting the readSourceContentLines goroutine!")
	}()
	return rowsStream
}

type lineProcessingJob struct {
	lineNumber  int
	lineContent string
}

func runLineProcessingWorker(
	ctx context.Context,
	logger *slog.Logger,
	wg *sync.WaitGroup,
	workerId int,
	jobsStream <-chan lineProcessingJob,
	lineDetectionsStream chan<- LineDetections,
) {
	logger = logger.With("workerId", workerId)
	go func() {
		defer wg.Done()
		processedLine := runLineProcessing(ctx, logger, jobsStream)
		for {
			select {
			case <-ctx.Done():
				return
			case detection, ok := <-processedLine:
				if !ok {
					return
				}
				lineDetectionsStream <- detection
			}

		}
	}()
}

type detectionProcessResult struct {
	HighestThreatLevel ThreatLevel
	Detections         []Detection
}

func runDetector(ctx context.Context, line string, lineNumber int) <-chan detectionProcessResult {
	stream := make(chan detectionProcessResult)
	highestThreatLevel := ZeroLevel
	go func() {
		defer close(stream)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			emailDetector := NewEmailDetector()
			emailDetection := emailDetector.Match(line)
			if len(emailDetection) > 0 {
				if highestThreatLevel < emailDetector.GetThreatLevel() {
					highestThreatLevel = emailDetector.GetThreatLevel()
				}
			}

			stream <- detectionProcessResult{
				HighestThreatLevel: highestThreatLevel,
				Detections:         emailDetection,
			}
		}
	}()

	return stream
}

func runLineProcessing(ctx context.Context, logger *slog.Logger, jobsStream <-chan lineProcessingJob) <-chan LineDetections {
	detectionsStream := make(chan LineDetections)
	logger.Debug("starting the line processing worker")
	go func() {
		defer close(detectionsStream)
		for {
			select {
			case <-ctx.Done():
				return
			case job, ok := <-jobsStream:
				if !ok {
					return
				}

				result := <-runDetector(ctx, job.lineContent, job.lineNumber)

				detectionsStream <- LineDetections{
					LineNumber:         job.lineNumber,
					Detections:         result.Detections,
					HighestThreatLevel: result.HighestThreatLevel,
				}

			}
		}
	}()

	return detectionsStream
}

type collectDetectionResult struct {
	ByLineDetections   []LineDetections
	HighestThreatLevel ThreatLevel
}

func collectDetections(
	ctx context.Context,
	logger *slog.Logger,
	lineDetectionsStream <-chan LineDetections,
) <-chan collectDetectionResult {
	res := make(chan collectDetectionResult)
	ByLineDetections := make([]LineDetections, 0)
	highestThreatLevel := ZeroLevel
	go func() {
		defer close(res)
		for {
			select {
			case <-ctx.Done():
				return
			case lineDetection, ok := <-lineDetectionsStream:
				if !ok {
					res <- collectDetectionResult{
						ByLineDetections:   ByLineDetections,
						HighestThreatLevel: highestThreatLevel,
					}
					return
				}

				// ignore lines without leak/detections
				if len(lineDetection.Detections) == 0 {
					continue
				}

				ByLineDetections = append(ByLineDetections, lineDetection)
				if lineDetection.HighestThreatLevel > highestThreatLevel {
					highestThreatLevel = lineDetection.HighestThreatLevel
				}

			}
		}
	}()

	return res
}

func analyzeSource(ctx context.Context, logger *slog.Logger, s Source) SourceAnalyzeResult {
	startTime := time.Now()
	logger = logger.With("sourceType", fmt.Sprintf("%s", s.SourceType))
	logger.Info("analyzing source", "source", s)

	var (
		jobs                 = make(chan lineProcessingJob)
		lineDetectionsStream = make(chan LineDetections)
		resultBuildingDone   = make(chan bool)
		nbWorker             = 1
		wg                   = &sync.WaitGroup{}
		result               = SourceAnalyzeResult{Source: s}
		errGroup             error
	)

	// start workers
	wg.Add(nbWorker)
	for workerId := 0; workerId < nbWorker; workerId++ {
		runLineProcessingWorker(ctx, logger, wg, workerId, jobs, lineDetectionsStream)
	}

	go func() {
		res := <-collectDetections(ctx, logger, lineDetectionsStream)
		result.ByLineDetections = res.ByLineDetections
		result.HighestThreatLevel = res.HighestThreatLevel
		close(resultBuildingDone)
	}()

	var nbLineScanned int
	for row := range readSourceContentLines(ctx, logger, s) {
		if row.Err != nil {
			errGroup = errors.Join(errGroup, row.Err)
			continue
		}

		job := lineProcessingJob{
			lineNumber:  row.LineNumber,
			lineContent: row.Line,
		}

		logger.Debug("queuing job", "job", job)
		nbLineScanned = row.LineNumber
		jobs <- job
	}

	close(jobs)
	wg.Wait()
	close(lineDetectionsStream)

	<-resultBuildingDone

	result.AnalyzeTime = time.Since(startTime)
	result.NumberOfLinesScanned = nbLineScanned
	result.Err = errGroup

	return result
}

func analyzeSourceWorker(ctx context.Context, logger *slog.Logger, wg *sync.WaitGroup, sourcesStream <-chan Source, resultsStream chan<- SourceAnalyzeResult) {
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case source, ok := <-sourcesStream:
				if !ok {
					return
				}

				resultsStream <- analyzeSource(ctx, logger, source)
			}
		}
	}()
}

func collectSourcesAnalyzeResult(ctx context.Context, logger *slog.Logger, sourceAnalyzeResultsStream <-chan SourceAnalyzeResult) <-chan AnalyzeResult {
	var (
		result                      = make(chan AnalyzeResult)
		sourceAnalyzedResults       = make([]SourceAnalyzeResult, 0)
		highestThreatLevel          = ZeroLevel
		errGroup                    error
		numberOfSourcesWithPIILeaks int
	)

	go func() {
		defer close(result)
		for {
			select {
			case <-ctx.Done():
				return
			case r, ok := <-sourceAnalyzeResultsStream:
				if !ok {
					result <- AnalyzeResult{
						NumberOfAnalyzedSources:     len(sourceAnalyzedResults),
						SourceAnalyzeResults:        sourceAnalyzedResults,
						NumberOfSourcesWithPIILeaks: numberOfSourcesWithPIILeaks,
						HighestThreatLevel:          highestThreatLevel,
						Err:                         errGroup,
					}
					return
				}

				sourceAnalyzedResults = append(sourceAnalyzedResults, r)

				if len(r.ByLineDetections) > 0 {
					numberOfSourcesWithPIILeaks++
				}

				if highestThreatLevel < r.HighestThreatLevel {
					highestThreatLevel = r.HighestThreatLevel
				}

				if r.Err != nil {
					logger.Error("error happens when analyzing source", "source", r.Source, "err", r.Err)
					errGroup = errors.Join(errGroup, r.Err)
				}
			}
		}
	}()
	return result
}

func analyzeSources(ctx context.Context, logger *slog.Logger, sources ...Source) AnalyzeResult {
	startTime := time.Now()
	var (
		result                     AnalyzeResult
		jobsStream                 = make(chan Source)
		sourceAnalyzeResultsStream = make(chan SourceAnalyzeResult)
		sourceAnalyzeDone          = make(chan bool)
		wg                         = &sync.WaitGroup{}
		nbWorkers                  = len(sources)
	)

	wg.Add(nbWorkers)
	for i := 0; i < nbWorkers; i++ {
		analyzeSourceWorker(ctx, logger, wg, jobsStream, sourceAnalyzeResultsStream)
	}

	go func() {
		defer close(sourceAnalyzeDone)
		result = <-collectSourcesAnalyzeResult(ctx, logger, sourceAnalyzeResultsStream)
	}()

	for _, source := range sources {
		jobsStream <- source
	}
	close(jobsStream)

	wg.Wait()
	close(sourceAnalyzeResultsStream)
	<-sourceAnalyzeDone

	result.TotalAnalyzeDuration = time.Since(startTime)

	return result
}
