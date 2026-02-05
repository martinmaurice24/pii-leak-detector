package piileakdetector

import (
	"fmt"
	"regexp"
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
