# PII Leak Detector
This is useful if you want to detect leaks in any given content.  
It allows you to take advantage of existing detectors but also gives you the opportunity to build your own.  
This project demonstrates practical usage of Go concurrency patterns.

## How to install it
```bash
go get github.com/martinmaurice24/pii-leak-detector
```

## Some keywords
**Detector**: A piece of logic that scans content to find a match like email, IP, or whatever you have defined in your logic.

**Leak**: Anything that is matched in given content by a detector.

**Source**: Where we find the content that will be analyzed to detect leaks (string, file, URL).


## How it works

You begin by initializing an analyzer with sources, detectors, and the number of workers.
The number of workers defines the number of sources that must be analyzed concurrently (by default len(sources)).
The detectors will go through the content and detect leaks (by default: Email and IPv4 detectors are configured).

### How This Works Technically

```
Sources (File/String/URL)
    ↓
[Source Workers - Concurrent Processing]
    ├─→ Worker 1: Read Source 1 → Split into Lines
    ├─→ Worker 2: Read Source 2 → Split into Lines
    └─→ Worker N: Read Source N → Split into Lines
    ↓
[Line Processing Workers - Concurrent Processing]
    ├─→ Line Worker: Run Detectors (Email, IPv4, Custom) → Find Leaks
    ├─→ Line Worker: Run Detectors (Email, IPv4, Custom) → Find Leaks
    └─→ Line Worker: Run Detectors (Email, IPv4, Custom) → Find Leaks
    ↓
[Aggregation]
    → Collect All Detections
    → Calculate Threat Levels
    → Build Source Analysis Results
    ↓
Return Final AnalysisResult
```

The sources are handled by the workers and the results are aggregated and returned.
Each worker reads the source content depending on the type (file, string, or URL) and then splits the content by line.
The lines are handled by another group of workers that call the detectors to find potential leaks.
We collect everything to build a source analysis result that will be part of the final result.

## Usage examples
Analyze file content
```go
import (
    "context"
    "log/slog"
    piileakdetector "github.com/martinmaurice24/pii-leak-detector"
)

func main() {
    ctx := context.Background()
    logger := slog.Default()

    sources := []piileakdetector.Source{
        {
            SourceType: piileakdetector.FileSource,
            FilePath:   "/tmp/filename.txt",
        },
    }

    analyzer := piileakdetector.NewAnalyzer(logger, sources)
    result := analyzer.Run(ctx)
    if result.Err != nil {
        log.Fatalf("error happened during source analysis, err: %v", result.Err)
    }

    fmt.Println(result)
}

```

Analyze content downloadable at the given URL
```go
import (
    "context"
    "log/slog"
    piileakdetector "github.com/martinmaurice24/pii-leak-detector"
)

func main() {
    ctx := context.Background()
    logger := slog.Default()

    sources := []piileakdetector.Source{
        {
            SourceType: piileakdetector.URLSource,
            URL:        "https://url-of-the-content-to-scan.com",
        },
    }

    analyzer := piileakdetector.NewAnalyzer(logger, sources)
    result := analyzer.Run(ctx)
    if result.Err != nil {
        log.Fatalf("error happened during source analysis, err: %v", result.Err)
    }

    fmt.Println(result)
}

```

Analyze a given content
```go
import (
    "context"
    "log/slog"
    piileakdetector "github.com/martinmaurice24/pii-leak-detector"
)

func main() {
    sources := []piileakdetector.Source{
        {
            SourceType: piileakdetector.StringSource,
            Content:    "New user with email john@doe.com registered with success!",
        },
    }

    analyzer := piileakdetector.NewAnalyzer(slog.Default(), sources)
    result := analyzer.Run(context.Background())
    if result.Err != nil {
        log.Fatalf("error happened during source analysis, err: %v", result.Err)
    }

    fmt.Println(result)
}
```

## Customization
You can create your own custom detector by implementing the `Detector` interface.
### How to create your custom detector
```go
type Detector interface {
    Match(line string) []Detection
    GetThreatLevel() ThreatLevel
}

type CustomDetector struct{}

func NewCustomDetector() CustomDetector {
	return CustomDetector{}
}

func (cd CustomDetector) Match(line string) []Detection {
	// write your logic here
	return nil
}

func (cd CustomDetector) GetThreatLevel() ThreatLevel {
	// return the threat level associated with this detector
	return MediumLevel
}
```
It's as simple as that!
You can create as many detectors as you want, then configure the analyzer to use them as follows:
```go
    // Initialize the analyzer with the detectors that it should use
    // Note that this will overwrite the default detectors
    // So if you wish to use them, you must add them to the list
    analyzer := piileakdetector.NewAnalyzer(
        logger,
        sources,
        piileakdetector.WithDetectors(
            NewCustomDetector(),
        ),
        piileakdetector.WithDetectorRunningMode(piileakdetector.FanOutFanInMode)
    )
```
You have currently two modes for running detectors:
- **SequentialMode**: In this mode, detectors are ran one after the other 
- **FanOutFanInMode**: In this one, the detectors are run in across many workers (runtime.NumCPU) and the results are aggregated

## CLI
You can use the CLI to detect email and IPv4 leaks in given content.
First install it by running:
```bash
go install github.com/martinmaurice24/pii-leak-detector/cmd/pii-leak-detector@latest

# rename the binary if you want by doing
mv $(go env GOPATH)/bin/cli $(go env GOPATH)/bin/pii

# Make sure the $(go env GOPATH)/bin folder is in your $PATH
# that way you could access the binary directly by typing the name, which is pii in this example
```

**Example 1: Analyze content directly**
```bash
pii -content="this file contains a leak: test@test.com\n"
```

Result:
```

❌  Leaks found in 1 file(s) ❌ 

Number of sources analyzed: 1
Number of sources with PII leaks: 1
Highest Threat Level Found: CriticalLevel
Some Errors Caught: false
Process Duration In Milliseconds: 450.542µs

┌───────────────────────────────────────────────────────┬──────────────────────┬─────────────┬───────────────┬────────────────┬───────────────┐
│                        SOURCE                         │ HIGHEST THREAT LEVEL │ LINE NUMBER │     LEAK      │    CATEGORY    │ THREAT LEVEL  │
├───────────────────────────────────────────────────────┼──────────────────────┼─────────────┼───────────────┼────────────────┼───────────────┤
│ Source is a string: this file contains a leak: tes... │ CriticalLevel        │ 1           │ test@test.com │ EmailDetection │ CriticalLevel │
└───────────────────────────────────────────────────────┴──────────────────────┴─────────────┴───────────────┴────────────────┴───────────────┘
```

**Example 2: Analyze multiple files**

Analyze 2 files (one of the files contains leaks, not the other one):
```bash
pii -files=./inputs/logs_clean.txt,./inputs/logs_with_pii.txt
```

Result:
```
❌  Leaks found in 1 file(s) ❌ 

Number of sources analyzed: 2
Number of sources with PII leaks: 1
Highest Threat Level Found: CriticalLevel
Some Errors Caught: false
Process Duration In Milliseconds: 2.726292ms

┌──────────────────────────────────────────────┬──────────────────────┬─────────────┬───────────────────────────┬────────────────┬───────────────┐
│                    SOURCE                    │ HIGHEST THREAT LEVEL │ LINE NUMBER │           LEAK            │    CATEGORY    │ THREAT LEVEL  │
├──────────────────────────────────────────────┼──────────────────────┼─────────────┼───────────────────────────┼────────────────┼───────────────┤
│ Source file path: ./inputs/logs_with_pii.txt │ CriticalLevel        │ 4           │ john.doe@example.com      │ EmailDetection │ CriticalLevel │
│                                              │                      │             ├───────────────────────────┼────────────────┼───────────────┤
│                                              │                      │             │ jane.doe@example.com      │ EmailDetection │ CriticalLevel │
│                                              │                      ├─────────────┼───────────────────────────┼────────────────┼───────────────┤
│                                              │                      │ 5           │ 192.168.1.105             │ IpDetection    │ CriticalLevel │
│                                              │                      ├─────────────┼───────────────────────────┼────────────────┼───────────────┤
│                                              │                      │ 6           │ sarah.connor@techcorp.com │ EmailDetection │ CriticalLevel │
│                                              │                      ├─────────────┼───────────────────────────┼────────────────┼───────────────┤
│                                              │                      │ 9           │ admin@company.org         │ EmailDetection │ CriticalLevel │
│                                              │                      ├─────────────┼───────────────────────────┼────────────────┼───────────────┤
│                                              │                      │ 10          │ 10.0.0.58                 │ IpDetection    │ CriticalLevel │
│                                              │                      ├─────────────┼───────────────────────────┼────────────────┼───────────────┤
│                                              │                      │ 11          │ 203.0.113.42              │ IpDetection    │ CriticalLevel │
│                                              │                      ├─────────────┼───────────────────────────┼────────────────┼───────────────┤
│                                              │                      │ 14          │ michael.smith@startup.io  │ EmailDetection │ CriticalLevel │
│                                              │                      ├─────────────┼───────────────────────────┼────────────────┼───────────────┤
│                                              │                      │ 17          │ 172.16.254.1              │ IpDetection    │ CriticalLevel │
└──────────────────────────────────────────────┴──────────────────────┴─────────────┴───────────────────────────┴────────────────┴───────────────┘
```

## How This Could Be Used in Real-Life Scenarios
This could be put behind an API endpoint that accepts content and responds with detected leaks in JSON format.
You could create detectors that call external services to detect specific things like names or locations.
One of those services may be a Python API that exposes an endpoint to take advantage of spaCy for NLP tasks, or a call to an LLM for another detection task.
You can really compose things in different ways to match your use case.

## Future Improvements
- Add more pattern detectors
- Accept directories as sources
- Allow users to override the source readers
- Add masking functionality
- Add different strategies to run the detectors (Pipe, Parallel)