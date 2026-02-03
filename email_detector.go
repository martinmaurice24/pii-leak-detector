package main

import "regexp"

type EmailDetector struct {
	threatLevel ThreatLevel
	category    DetectionCategory
}

func NewEmailDetector() Detector {
	return EmailDetector{
		threatLevel: CriticalLevel,
		category:    EmailDetection,
	}
}

func (ed EmailDetector) Match(line string) []Detection {
	emailPattern := `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
	reg := regexp.MustCompile(emailPattern)
	detections := make([]Detection, 0)
	for _, match := range reg.FindAllString(line, -1) {
		detections = append(detections, Detection{
			DetectionCategory: ed.category,
			Leak:              match,
			ThreatLevel:       ed.threatLevel,
		})
	}
	return detections
}

func (ed EmailDetector) GetThreatLevel() ThreatLevel {
	return CriticalLevel
}
