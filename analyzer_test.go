package main

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"testing"
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := 0
			linesStream := readSourceContentLines(tt.ctx, tt.logger, tt.source)
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

func Test_analyzeSource(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		s           Source
		want        SourceAnalysisResult
		expectedErr error
	}{
		{
			name: "",
			ctx:  context.Background(),
			s: Source{
				SourceType: StringSource,
				Content:    "Hello jack@test.com.\nContact her at tata@test.com.\nBye\n.",
			},
			want: SourceAnalysisResult{
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
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeSource(tt.ctx, slog.Default(), tt.s)
			require.NoError(t, got.Err)

			assert.Equal(t, tt.want.ByLineDetections, got.ByLineDetections)
			assert.Equal(t, tt.want.HighestThreatLevel, got.HighestThreatLevel)
			assert.Equal(
				t,
				tt.want.NumberOfLinesScanned,
				got.NumberOfLinesScanned,
				"Expected NumberOfLinesScanned %v got %v",
				tt.want.NumberOfLinesScanned,
				got.NumberOfLinesScanned,
			)
			assert.Equal(t, tt.s, got.Source)
		})
	}
}
