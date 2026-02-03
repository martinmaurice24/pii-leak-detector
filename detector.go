package main

import "fmt"

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
		"category:%s; leak:%s; threat_level:%s",
		d.DetectionCategory,
		d.Leak,
		d.ThreatLevel,
	)
}

type Detector interface {
	Match(line string) []Detection
	GetThreatLevel() ThreatLevel
}
