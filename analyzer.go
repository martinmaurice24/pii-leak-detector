package piileakdetector

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

var (
	ReadSourceErr = errors.New("failed to read the source")
)

type (
	LineDetections struct {
		LineNumber         int
		Detections         []Detection
		HighestThreatLevel ThreatLevel
	}

	SourceAnalysisResult struct {
		// the source of data that was analyzed (i.e: fileName)
		Source               Source
		NumberOfLinesScanned int
		ByLineDetections     []LineDetections
		HighestThreatLevel   ThreatLevel
		AnalysisTime         time.Duration
		Err                  error
	}

	AnalysisResult struct {
		NumberOfAnalyzedSources     int
		SourceAnalysisResults       []SourceAnalysisResult
		NumberOfSourcesWithPIILeaks int
		HighestThreatLevel          ThreatLevel
		TotalAnalysisDuration       time.Duration
		Err                         error
	}

	contentRow struct {
		Err        error
		Line       string
		LineNumber int
	}
)

type AnalyzerConfig struct {
	logger               *slog.Logger
	sources              []Source
	detectors            Detectors
	detectorsRunningMode DetectorsRunningMode
	nbSourceWorkers      int
}

type Option func(*AnalyzerConfig)

func WithNumberOfSourceWorkers(n int) Option {
	return func(config *AnalyzerConfig) {
		config.nbSourceWorkers = n
	}
}

func WithDetectors(detectors ...Detector) Option {
	return func(config *AnalyzerConfig) {
		config.detectors = detectors
	}
}

func WithDetectorRunningMode(mode DetectorsRunningMode) Option {
	return func(config *AnalyzerConfig) {
		config.detectorsRunningMode = mode
	}
}

func NewAnalyzer(logger *slog.Logger, sources []Source, options ...Option) *AnalyzerConfig {
	config := &AnalyzerConfig{
		logger:  logger,
		sources: sources,
	}

	for _, option := range options {
		option(config)
	}

	if len(config.detectors) == 0 {
		config.detectors = Detectors{
			NewEmailDetector(),
			NewIPv4Detector(),
		}
	}

	if config.detectorsRunningMode == 0 {
		config.detectorsRunningMode = SequentialMode
	}

	if config.nbSourceWorkers == 0 {
		config.nbSourceWorkers = len(sources)
	}

	return config
}

func (ac *AnalyzerConfig) Run(ctx context.Context) AnalysisResult {
	var (
		startTime                   = time.Now()
		logger                      = ac.logger
		result                      AnalysisResult
		jobsStream                  = make(chan Source)
		sourceAnalysisResultsStream = make(chan SourceAnalysisResult)
		sourceAnalysisDone          = make(chan bool)
		wg                          = &sync.WaitGroup{}
	)

	wg.Add(ac.nbSourceWorkers)
	for i := 0; i < ac.nbSourceWorkers; i++ {
		ac.analyzeSourceWorker(ctx, wg, jobsStream, sourceAnalysisResultsStream)
	}

	go func() {
		defer close(sourceAnalysisDone)
		result = <-ac.collectSourcesAnalysisResult(ctx, logger, sourceAnalysisResultsStream)
	}()

	for _, source := range ac.sources {
		jobsStream <- source
	}
	close(jobsStream)

	wg.Wait()
	close(sourceAnalysisResultsStream)
	<-sourceAnalysisDone

	result.TotalAnalysisDuration = time.Since(startTime)

	return result
}

func (ac *AnalyzerConfig) analyzeSourceWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	sourcesStream <-chan Source,
	resultsStream chan<- SourceAnalysisResult,
) {
	go func() {
		defer wg.Done()
		for source := range sourcesStream {
			resultsStream <- ac.analyzeSource(ctx, source)
		}
	}()
}

func (ac *AnalyzerConfig) analyzeSource(ctx context.Context, s Source) SourceAnalysisResult {
	startTime := time.Now()
	logger := ac.logger.With("source", fmt.Sprintf("%s", s))
	logger.Info("analyzing source")

	var (
		jobs                 = make(chan lineProcessingJob)
		lineDetectionsStream = make(chan LineDetections)
		resultBuildingDone   = make(chan bool)
		nbWorker             = 1
		wg                   = &sync.WaitGroup{}
		result               = SourceAnalysisResult{Source: s}
		errGroup             error
	)

	// start workers
	wg.Add(nbWorker)
	for workerId := 0; workerId < nbWorker; workerId++ {
		ac.runLineProcessingWorker(ctx, logger, wg, workerId, jobs, lineDetectionsStream)
	}

	go func() {
		res := <-ac.collectDetections(ctx, logger, lineDetectionsStream)
		result.ByLineDetections = res.ByLineDetections
		result.HighestThreatLevel = res.HighestThreatLevel
		close(resultBuildingDone)
	}()

	var nbLineScanned int
	for row := range ac.readSourceContentLines(ctx, logger, s) {
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

	result.AnalysisTime = time.Since(startTime)
	result.NumberOfLinesScanned = nbLineScanned
	result.Err = errGroup

	return result
}

func (ac *AnalyzerConfig) collectSourcesAnalysisResult(
	ctx context.Context,
	logger *slog.Logger,
	sourceAnalysisResultsStream <-chan SourceAnalysisResult,
) <-chan AnalysisResult {
	var (
		result                      = make(chan AnalysisResult)
		sourceAnalysisResults       = make([]SourceAnalysisResult, 0)
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
			case r, ok := <-sourceAnalysisResultsStream:
				if !ok {
					result <- AnalysisResult{
						NumberOfAnalyzedSources:     len(sourceAnalysisResults),
						SourceAnalysisResults:       sourceAnalysisResults,
						NumberOfSourcesWithPIILeaks: numberOfSourcesWithPIILeaks,
						HighestThreatLevel:          highestThreatLevel,
						Err:                         errGroup,
					}
					return
				}

				sourceAnalysisResults = append(sourceAnalysisResults, r)

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

func (ac *AnalyzerConfig) readSourceContentLines(ctx context.Context, logger *slog.Logger, s Source) <-chan contentRow {
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

		scanner := bufio.NewScanner(bytes.NewReader(sourceContent))
		lineNumber := 1
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := scanner.Text()
			if scanner.Err() == io.EOF {
				logger.Debug("End of file")
				break
			} else if scanner.Err() != nil {
				logger.Error(err.Error(), "line", line)
			} else {
				logger.Debug("Extracting line", "nb", lineNumber, "line", line)
			}

			rowsStream <- contentRow{
				Err:        err,
				Line:       line,
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

func (ac *AnalyzerConfig) runLineProcessingWorker(
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
		for processedLine := range ac.runLineProcessing(ctx, logger, jobsStream) {
			lineDetectionsStream <- processedLine
		}
	}()
}

type detectionProcessResult struct {
	HighestThreatLevel ThreatLevel
	Detections         []Detection
}

func (ac *AnalyzerConfig) runLeakDetectors(ctx context.Context, line string) <-chan detectionProcessResult {
	stream := make(chan detectionProcessResult)

	go func() {
		defer close(stream)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			detections, highestThreatLevel := ac.detectors.Run(ctx, line, ac.detectorsRunningMode)

			stream <- detectionProcessResult{
				HighestThreatLevel: highestThreatLevel,
				Detections:         detections,
			}
		}
	}()

	return stream
}

func (ac *AnalyzerConfig) runLineProcessing(
	ctx context.Context,
	logger *slog.Logger,
	jobsStream <-chan lineProcessingJob,
) <-chan LineDetections {
	logger.Debug("starting the line processing worker")
	detectionsStream := make(chan LineDetections)
	go func() {
		defer close(detectionsStream)
		for job := range jobsStream {
			result := <-ac.runLeakDetectors(ctx, job.lineContent)
			if ctx.Err() != nil {
				return
			}
			detectionsStream <- LineDetections{
				LineNumber:         job.lineNumber,
				Detections:         result.Detections,
				HighestThreatLevel: result.HighestThreatLevel,
			}
		}
	}()

	return detectionsStream
}

type collectDetectionResult struct {
	ByLineDetections   []LineDetections
	HighestThreatLevel ThreatLevel
}

func (ac *AnalyzerConfig) collectDetections(
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
					collectedResult := collectDetectionResult{
						ByLineDetections:   ByLineDetections,
						HighestThreatLevel: highestThreatLevel,
					}

					logger.Debug("result collected", "result", collectedResult, "ok", ok)
					res <- collectedResult
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
