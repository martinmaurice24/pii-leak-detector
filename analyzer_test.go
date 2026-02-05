package piileakdetector

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"sort"
	"testing"
	"time"
)

func Test_readSourceContentLines(t *testing.T) {
	logger := slog.Default()
	slog.SetLogLoggerLevel(slog.LevelDebug)

	tests := []struct {
		name                     string
		ctx                      context.Context
		logger                   *slog.Logger
		source                   Source
		want                     []contentRow
		expectedErr              error
		expectedLineScannedCount int
	}{
		{
			name:   "Should fail because the source is not correct",
			ctx:    context.Background(),
			logger: logger,
			source: Source{
				SourceType: FileSource,
				FilePath:   "invalid_source.txt",
			},
			want: []contentRow{
				{
					LineNumber: 0,
					Line:       "",
				},
			},
			expectedErr: ReadSourceErr,
		},
		{
			name:   "Should read the source content and send the correct rows",
			ctx:    context.Background(),
			logger: logger,
			source: Source{
				SourceType: StringSource,
				Content:    "Hello!\nMy name is John.\nNice to meet you.\n",
			},
			want: []contentRow{
				{
					Err:        nil,
					Line:       "Hello!\n",
					LineNumber: 1,
				},
				{
					Err:        nil,
					Line:       "My name is John.\n",
					LineNumber: 2,
				},
				{
					Err:        nil,
					Line:       "Nice to meet you.\n",
					LineNumber: 3,
				},
			},
			expectedLineScannedCount: 3,
		},
	}

	analyzer := AnalyzerConfig{logger: slog.Default()}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := 0
			linesStream := analyzer.readSourceContentLines(tt.ctx, tt.logger, tt.source)
			lineScanned := 0
			for row := range linesStream {
				assert.Equal(t, tt.want[i].Line, row.Line)
				assert.Equal(t, tt.want[i].LineNumber, row.LineNumber)

				if tt.expectedErr != nil {
					require.ErrorIs(t, row.Err, ReadSourceErr)
				} else {
					assert.Equal(t, tt.want[i].Err, row.Err)
				}
				i++
				lineScanned = row.LineNumber
			}

			assert.Equal(t, tt.expectedLineScannedCount, lineScanned)

		})
	}
}

func sortSourceAnalysisResults(results []SourceAnalysisResult) {
	sort.Slice(results, func(i, j int) bool {
		return results[i].Source.Content < results[j].Source.Content
	})
}

func TestAnalyzerConfig_Run(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		detectors   []Detector
		sources     []Source
		want        AnalysisResult
		expectedErr error
	}{
		{
			name: "Should detect emails in single source",
			ctx:  context.Background(),
			detectors: []Detector{
				NewEmailDetector(),
			},
			sources: []Source{
				{
					SourceType: StringSource,
					Content:    "Hello jack@test.com.\nContact her at tata@test.com.\nBye\n.",
				},
			},
			want: AnalysisResult{
				NumberOfAnalyzedSources: 1,
				SourceAnalysisResults: []SourceAnalysisResult{
					{
						Source: Source{
							SourceType: StringSource,
							Content:    "Hello jack@test.com.\nContact her at tata@test.com.\nBye\n.",
						},
						ByLineDetections: []LineDetections{
							{
								LineNumber: 1,
								Detections: []Detection{
									{
										DetectionCategory: EmailDetection,
										Leak:              "jack@test.com",
										ThreatLevel:       CriticalLevel,
									},
								},
								HighestThreatLevel: CriticalLevel,
							},
							{
								LineNumber: 2,
								Detections: []Detection{
									{
										DetectionCategory: EmailDetection,
										Leak:              "tata@test.com",
										ThreatLevel:       CriticalLevel,
									},
								},
								HighestThreatLevel: CriticalLevel,
							},
						},
						HighestThreatLevel:   CriticalLevel,
						NumberOfLinesScanned: 3,
					},
				},
				NumberOfSourcesWithPIILeaks: 1,
				HighestThreatLevel:          CriticalLevel,
				Err:                         nil,
			},
			expectedErr: nil,
		},
		{
			name: "Should detect IPv4 addresses in single source",
			ctx:  context.Background(),
			detectors: []Detector{
				NewIPv4Detector(),
			},
			sources: []Source{
				{
					SourceType: StringSource,
					Content:    "Server IP: 192.168.1.1\nDatabase at 10.0.0.5\n",
				},
			},
			want: AnalysisResult{
				NumberOfAnalyzedSources: 1,
				SourceAnalysisResults: []SourceAnalysisResult{
					{
						Source: Source{
							SourceType: StringSource,
							Content:    "Server IP: 192.168.1.1\nDatabase at 10.0.0.5\n",
						},
						ByLineDetections: []LineDetections{
							{
								LineNumber: 1,
								Detections: []Detection{
									{
										DetectionCategory: IpDetection,
										Leak:              "192.168.1.1",
										ThreatLevel:       CriticalLevel,
									},
								},
								HighestThreatLevel: CriticalLevel,
							},
							{
								LineNumber: 2,
								Detections: []Detection{
									{
										DetectionCategory: IpDetection,
										Leak:              "10.0.0.5",
										ThreatLevel:       CriticalLevel,
									},
								},
								HighestThreatLevel: CriticalLevel,
							},
						},
						HighestThreatLevel:   CriticalLevel,
						NumberOfLinesScanned: 2,
					},
				},
				NumberOfSourcesWithPIILeaks: 1,
				HighestThreatLevel:          CriticalLevel,
				Err:                         nil,
			},
			expectedErr: nil,
		},
		{
			name: "Should detect both emails and IPv4 addresses with multiple detectors",
			ctx:  context.Background(),
			detectors: []Detector{
				NewEmailDetector(),
				NewIPv4Detector(),
			},
			sources: []Source{
				{
					SourceType: StringSource,
					Content:    "Contact: admin@example.com from 192.168.1.100\nServer: 10.0.0.1\n",
				},
			},
			want: AnalysisResult{
				NumberOfAnalyzedSources: 1,
				SourceAnalysisResults: []SourceAnalysisResult{
					{
						Source: Source{
							SourceType: StringSource,
							Content:    "Contact: admin@example.com from 192.168.1.100\nServer: 10.0.0.1\n",
						},
						ByLineDetections: []LineDetections{
							{
								LineNumber: 1,
								Detections: []Detection{
									{
										DetectionCategory: EmailDetection,
										Leak:              "admin@example.com",
										ThreatLevel:       CriticalLevel,
									},
									{
										DetectionCategory: IpDetection,
										Leak:              "192.168.1.100",
										ThreatLevel:       CriticalLevel,
									},
								},
								HighestThreatLevel: CriticalLevel,
							},
							{
								LineNumber: 2,
								Detections: []Detection{
									{
										DetectionCategory: IpDetection,
										Leak:              "10.0.0.1",
										ThreatLevel:       CriticalLevel,
									},
								},
								HighestThreatLevel: CriticalLevel,
							},
						},
						HighestThreatLevel:   CriticalLevel,
						NumberOfLinesScanned: 2,
					},
				},
				NumberOfSourcesWithPIILeaks: 1,
				HighestThreatLevel:          CriticalLevel,
				Err:                         nil,
			},
			expectedErr: nil,
		},
		{
			name: "Should return zero results for clean content",
			ctx:  context.Background(),
			detectors: []Detector{
				NewEmailDetector(),
				NewIPv4Detector(),
			},
			sources: []Source{
				{
					SourceType: StringSource,
					Content:    "This is clean content\nNo PII data\nJust regular text\n",
				},
			},
			want: AnalysisResult{
				NumberOfAnalyzedSources: 1,
				SourceAnalysisResults: []SourceAnalysisResult{
					{
						Source: Source{
							SourceType: StringSource,
							Content:    "This is clean content\nNo PII data\nJust regular text\n",
						},
						ByLineDetections:     []LineDetections{},
						HighestThreatLevel:   ZeroLevel,
						NumberOfLinesScanned: 3,
					},
				},
				NumberOfSourcesWithPIILeaks: 0,
				HighestThreatLevel:          ZeroLevel,
				Err:                         nil,
			},
			expectedErr: nil,
		},
		{
			name: "Should handle empty content",
			ctx:  context.Background(),
			detectors: []Detector{
				NewEmailDetector(),
			},
			sources: []Source{
				{
					SourceType: StringSource,
					Content:    "",
				},
			},
			want: AnalysisResult{
				NumberOfAnalyzedSources: 1,
				SourceAnalysisResults: []SourceAnalysisResult{
					{
						Source: Source{
							SourceType: StringSource,
							Content:    "",
						},
						ByLineDetections:     []LineDetections{},
						HighestThreatLevel:   ZeroLevel,
						NumberOfLinesScanned: 0,
					},
				},
				NumberOfSourcesWithPIILeaks: 0,
				HighestThreatLevel:          ZeroLevel,
				Err:                         nil,
			},
			expectedErr: nil,
		},
		{
			name: "Should detect multiple emails on same line",
			ctx:  context.Background(),
			detectors: []Detector{
				NewEmailDetector(),
			},
			sources: []Source{
				{
					SourceType: StringSource,
					Content:    "CC: user1@test.com, user2@test.com, admin@example.org\n",
				},
			},
			want: AnalysisResult{
				NumberOfAnalyzedSources: 1,
				SourceAnalysisResults: []SourceAnalysisResult{
					{
						Source: Source{
							SourceType: StringSource,
							Content:    "CC: user1@test.com, user2@test.com, admin@example.org\n",
						},
						ByLineDetections: []LineDetections{
							{
								LineNumber: 1,
								Detections: []Detection{
									{
										DetectionCategory: EmailDetection,
										Leak:              "user1@test.com",
										ThreatLevel:       CriticalLevel,
									},
									{
										DetectionCategory: EmailDetection,
										Leak:              "user2@test.com",
										ThreatLevel:       CriticalLevel,
									},
									{
										DetectionCategory: EmailDetection,
										Leak:              "admin@example.org",
										ThreatLevel:       CriticalLevel,
									},
								},
								HighestThreatLevel: CriticalLevel,
							},
						},
						HighestThreatLevel:   CriticalLevel,
						NumberOfLinesScanned: 1,
					},
				},
				NumberOfSourcesWithPIILeaks: 1,
				HighestThreatLevel:          CriticalLevel,
				Err:                         nil,
			},
			expectedErr: nil,
		},
		{
			name: "Should handle invalid file source and return error",
			ctx:  context.Background(),
			detectors: []Detector{
				NewEmailDetector(),
			},
			sources: []Source{
				{
					SourceType: FileSource,
					FilePath:   "/non/existent/file.txt",
				},
			},
			want: AnalysisResult{
				NumberOfAnalyzedSources: 1,
				SourceAnalysisResults: []SourceAnalysisResult{
					{
						Source: Source{
							SourceType: FileSource,
							FilePath:   "/non/existent/file.txt",
						},
						ByLineDetections:     []LineDetections{},
						HighestThreatLevel:   ZeroLevel,
						NumberOfLinesScanned: 0,
						Err:                  ReadSourceErr,
					},
				},
				NumberOfSourcesWithPIILeaks: 0,
				HighestThreatLevel:          ZeroLevel,
			},
			expectedErr: ReadSourceErr,
		},
		{
			name: "Should handle multiple sources with mixed results",
			ctx:  context.Background(),
			detectors: []Detector{
				NewEmailDetector(),
			},
			sources: []Source{
				{
					SourceType: StringSource,
					Content:    "Email: test@example.com\n",
				},
				{
					SourceType: StringSource,
					Content:    "No PII data here\nJust plain text\n",
				},
				{
					SourceType: StringSource,
					Content:    "Another email: admin@test.org\n",
				},
			},
			want: AnalysisResult{
				NumberOfAnalyzedSources: 3,
				SourceAnalysisResults: []SourceAnalysisResult{
					{
						Source: Source{
							SourceType: StringSource,
							Content:    "Another email: admin@test.org\n",
						},
						ByLineDetections: []LineDetections{
							{
								LineNumber: 1,
								Detections: []Detection{
									{
										DetectionCategory: EmailDetection,
										Leak:              "admin@test.org",
										ThreatLevel:       CriticalLevel,
									},
								},
								HighestThreatLevel: CriticalLevel,
							},
						},
						HighestThreatLevel:   CriticalLevel,
						NumberOfLinesScanned: 1,
					},
					{
						Source: Source{
							SourceType: StringSource,
							Content:    "Email: test@example.com\n",
						},
						ByLineDetections: []LineDetections{
							{
								LineNumber: 1,
								Detections: []Detection{
									{
										DetectionCategory: EmailDetection,
										Leak:              "test@example.com",
										ThreatLevel:       CriticalLevel,
									},
								},
								HighestThreatLevel: CriticalLevel,
							},
						},
						HighestThreatLevel:   CriticalLevel,
						NumberOfLinesScanned: 1,
					},
					{
						Source: Source{
							SourceType: StringSource,
							Content:    "No PII data here\nJust plain text\n",
						},
						ByLineDetections:     []LineDetections{},
						HighestThreatLevel:   ZeroLevel,
						NumberOfLinesScanned: 2,
					},
				},
				NumberOfSourcesWithPIILeaks: 2,
				HighestThreatLevel:          CriticalLevel,
				Err:                         nil,
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			analyzer := NewAnalyzer(slog.Default(), tt.sources, WithDetectors(tt.detectors...))
			got := analyzer.Run(tt.ctx)

			// Assert top-level AnalysisResult fields
			assert.Equal(t, tt.want.NumberOfAnalyzedSources, got.NumberOfAnalyzedSources, "NumberOfAnalyzedSources mismatch")
			assert.Equal(t, tt.want.NumberOfSourcesWithPIILeaks, got.NumberOfSourcesWithPIILeaks, "NumberOfSourcesWithPIILeaks mismatch")
			assert.Equal(t, tt.want.HighestThreatLevel, got.HighestThreatLevel, "HighestThreatLevel mismatch")
			assert.Equal(t, len(tt.want.SourceAnalysisResults), len(got.SourceAnalysisResults), "Number of SourceAnalysisResults mismatch")

			// Assert error handling
			if tt.expectedErr != nil {
				require.ErrorIs(t, got.Err, tt.expectedErr, "Expected error not found")
			} else {
				assert.NoError(t, got.Err, "Unexpected error occurred")
			}

			// Assert TotalAnalysisDuration is set and reasonable
			assert.Greater(t, got.TotalAnalysisDuration, time.Duration(0), "TotalAnalysisDuration should be greater than 0")

			// Assert each SourceAnalysisResult
			sortSourceAnalysisResults(got.SourceAnalysisResults)
			sortSourceAnalysisResults(tt.want.SourceAnalysisResults)

			for i, gotSourceResult := range got.SourceAnalysisResults {
				wantSourceResult := tt.want.SourceAnalysisResults[i]

				// Assert source
				assert.Equal(t, wantSourceResult.Source, gotSourceResult.Source, "Source[%d] mismatch", i)

				// Assert source analysis metrics
				assert.Equal(t, wantSourceResult.NumberOfLinesScanned, gotSourceResult.NumberOfLinesScanned, "Source[%d] NumberOfLinesScanned mismatch", i)
				assert.Equal(t, wantSourceResult.HighestThreatLevel, gotSourceResult.HighestThreatLevel, "Source[%d] HighestThreatLevel mismatch", i)
				assert.Greater(t, gotSourceResult.AnalysisTime, time.Duration(0), "Source[%d] AnalysisTime should be greater than 0", i)

				// Assert line-by-line detections
				require.Equal(t, len(wantSourceResult.ByLineDetections), len(gotSourceResult.ByLineDetections), "Source[%d] number of ByLineDetections mismatch", i)
				for j, gotLineDetection := range gotSourceResult.ByLineDetections {
					wantLineDetection := wantSourceResult.ByLineDetections[j]

					assert.Equal(t, wantLineDetection.LineNumber, gotLineDetection.LineNumber, "Source[%d] LineDetection[%d] LineNumber mismatch", i, j)
					assert.Equal(t, wantLineDetection.HighestThreatLevel, gotLineDetection.HighestThreatLevel, "Source[%d] LineDetection[%d] HighestThreatLevel mismatch", i, j)

					// Assert individual detections
					require.Equal(t, len(wantLineDetection.Detections), len(gotLineDetection.Detections), "Source[%d] LineDetection[%d] number of Detections mismatch", i, j)
					for k, gotDetection := range gotLineDetection.Detections {
						wantDetection := wantLineDetection.Detections[k]

						assert.Equal(t, wantDetection.DetectionCategory, gotDetection.DetectionCategory, "Source[%d] LineDetection[%d] Detection[%d] Category mismatch", i, j, k)
						assert.Equal(t, wantDetection.Leak, gotDetection.Leak, "Source[%d] LineDetection[%d] Detection[%d] Leak mismatch", i, j, k)
						assert.Equal(t, wantDetection.ThreatLevel, gotDetection.ThreatLevel, "Source[%d] LineDetection[%d] Detection[%d] ThreatLevel mismatch", i, j, k)
					}
				}

				// Assert source-level error
				if wantSourceResult.Err != nil {
					require.ErrorIs(t, gotSourceResult.Err, wantSourceResult.Err, "Source[%d] error mismatch", i)
				} else {
					assert.NoError(t, gotSourceResult.Err, "Source[%d] unexpected error", i)
				}
			}
		})
	}
}
