package main

type EmailDetector struct {
	RegexDetector
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
	return ed.RegexMatch(line, emailPattern, ed.category, ed.threatLevel)
}

func (ed EmailDetector) GetThreatLevel() ThreatLevel {
	return CriticalLevel
}
