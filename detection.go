package piileakdetector

import (
	"context"
	"fmt"
	"regexp"
	"sync"
)

type DetectionCategory int

const (
	EmailDetection DetectionCategory = iota
	IpDetection
)

func (t DetectionCategory) String() string {
	return [...]string{"EmailDetection", "IpDetection"}[t]
}

type ThreatLevel int

const (
	ZeroLevel ThreatLevel = iota
	LowLevel
	MediumLevel
	HighLevel
	CriticalLevel
)

func (t ThreatLevel) String() string {
	return [...]string{"ZeroLevel", "LowLevel", "MediumLevel", "HighLevel", "CriticalLevel"}[t]
}

type Detection struct {
	DetectionCategory DetectionCategory
	Leak              string
	ThreatLevel       ThreatLevel
}

func (d Detection) String() string {
	return fmt.Sprintf(
		"Category:%s\nLeak:%s\nThreat level:%s\n",
		d.DetectionCategory,
		d.Leak,
		d.ThreatLevel,
	)
}

type Detector interface {
	Match(line string) []Detection
	GetThreatLevel() ThreatLevel
}

type RegexDetector struct{}

func (RegexDetector) RegexMatch(line, pattern string, category DetectionCategory, level ThreatLevel) []Detection {
	reg := regexp.MustCompile(pattern)
	detections := make([]Detection, 0)
	for _, match := range reg.FindAllString(line, -1) {
		detections = append(detections, Detection{
			DetectionCategory: category,
			Leak:              match,
			ThreatLevel:       level,
		})
	}

	return detections
}

type DetectorsRunningMode int

const (
	SequentialMode DetectorsRunningMode = iota
	FanOutFanInMode
)

type Detectors []Detector

func (detectors Detectors) Run(
	ctx context.Context,
	content string,
	mode DetectorsRunningMode,
) ([]Detection, ThreatLevel) {
	if mode == FanOutFanInMode {
		return detectors.runInFanOutFanInMode(ctx, content)
	}

	return detectors.runInSequentialMode(ctx, content)
}

func (detectors Detectors) runInSequentialMode(
	ctx context.Context,
	content string,
) ([]Detection, ThreatLevel) {
	highestThreatLevel := ZeroLevel
	detectionsFound := make([]Detection, 0)
	for _, detector := range detectors {
		detections := detector.Match(content)
		if len(detections) > 0 {
			if highestThreatLevel < detector.GetThreatLevel() {
				highestThreatLevel = detector.GetThreatLevel()
			}
		}
		detectionsFound = append(detectionsFound, detections...)
	}

	return detectionsFound, highestThreatLevel
}

func (detectors Detectors) runInFanOutFanInMode(ctx context.Context, content string) ([]Detection, ThreatLevel) {
	nbWorkers := len(detectors)
	detectionResults := make([]<-chan []Detection, nbWorkers)
	detectorFuncStream := make(chan Detector, len(detectors))

	for _, detector := range detectors {
		detectorFuncStream <- detector
	}
	close(detectorFuncStream)

	for i := 0; i < nbWorkers; i++ {
		detectionResults[i] = findDetections(ctx, content, detectorFuncStream)
	}

	highestThreatLevel := ZeroLevel
	detectionsFound := make([]Detection, 0)

	for detections := range fanInDetectorsResults(ctx, detectionResults) {
		if len(detections) == 0 {
			continue
		}

		threatLevel := detections[0].ThreatLevel
		if highestThreatLevel < threatLevel {
			highestThreatLevel = threatLevel
		}

		detectionsFound = append(detectionsFound, detections...)
	}

	return detectionsFound, highestThreatLevel
}

func findDetections(ctx context.Context, content string, detectorsStream <-chan Detector) <-chan []Detection {
	detections := make(chan []Detection)
	go func() {
		defer close(detections)

		for {
			select {
			case <-ctx.Done():
				return
			case detector, ok := <-detectorsStream:
				if !ok {
					return
				}
				detections <- detector.Match(content)
			}
		}

	}()

	return detections
}

func fanInDetectorsResults(ctx context.Context, channels []<-chan []Detection) <-chan []Detection {
	var (
		multiplexedStream = make(chan []Detection)
		wg                = sync.WaitGroup{}
	)

	multiplex := func(channel <-chan []Detection) {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case detections, ok := <-channel:
				if !ok {
					return
				}
				multiplexedStream <- detections
			}
		}
	}

	for _, channel := range channels {
		wg.Add(1)
		go multiplex(channel)
	}

	go func() {
		wg.Wait()
		close(multiplexedStream)
	}()

	return multiplexedStream
}
