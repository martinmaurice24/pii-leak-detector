package main

type IPv4Detector struct {
	RegexDetector
	threatLevel ThreatLevel
	category    DetectionCategory
}

func NewIPv4Detector() Detector {
	return IPv4Detector{
		threatLevel: CriticalLevel,
		category:    IpDetection,
	}
}

func (d IPv4Detector) Match(line string) []Detection {
	pattern := `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
	return d.RegexMatch(line, pattern, d.category, d.threatLevel)
}

func (d IPv4Detector) GetThreatLevel() ThreatLevel {
	return CriticalLevel
}
