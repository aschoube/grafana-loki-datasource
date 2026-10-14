package loki

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/loki/v3/pkg/logql/syntax"
)

func runLogsVolumeQuery(ctx context.Context, api *LokiAPI, query *lokiQuery, opts ResponseOpts, plog log.Logger) (*backend.DataResponse, error) {
	parts, err := splitLogsVolumeQuery(*query)
	if err != nil {
		return nil, err
	}
	// There are at most three requests. Preserve chronological order when
	// merging, regardless of the order in which the requests finish.
	results := make([]*backend.DataResponse, len(parts))
	errors := make([]error, len(parts))
	var wg sync.WaitGroup
	for i := range parts {
		wg.Go(func() {
			results[i], errors[i] = runSingleQuery(ctx, api, &parts[i], opts, plog)
		})
	}
	wg.Wait()
	for i, result := range results {
		if errors[i] != nil {
			return nil, errors[i]
		}
		if result.Error != nil {
			// A partial histogram would present an incorrect total as success.
			result.Frames = nil
			return result, nil
		}
	}
	return mergeLogsVolumeResults(parts, results), nil
}

func mergeLogsVolumeResults(parts []lokiQuery, results []*backend.DataResponse) *backend.DataResponse {
	merged := &backend.DataResponse{Status: backend.StatusOK}
	series := make(map[data.Fingerprint][]*data.Frame)
	var executed []string
	var stats []data.QueryStat
	statIndexes := make(map[string]int)
	for i, result := range results {
		executed = append(executed, fmt.Sprintf("%s: %s; start=%s; end=%s; step=%s", parts[i].QueryType, parts[i].Expr, parts[i].Start.Format(time.RFC3339Nano), parts[i].End.Format(time.RFC3339Nano), parts[i].Step))
		for _, frame := range result.Frames {
			for _, stat := range frame.Meta.Stats {
				if index, ok := statIndexes[stat.DisplayName]; ok {
					stats[index].Value += stat.Value
				} else {
					statIndexes[stat.DisplayName] = len(stats)
					stats = append(stats, stat)
				}
			}
			frame.Meta.Stats = nil
			// Adjusted metric frames keep their labels on the value field. Use
			// fingerprints for lookup, but compare labels to resolve collisions.
			labels := frame.Fields[1].Labels
			key := labels.Fingerprint()
			var existing *data.Frame
			for _, candidate := range series[key] {
				if candidate.Fields[1].Labels.Equals(labels) {
					existing = candidate
					break
				}
			}
			if existing != nil {
				for row := 0; row < frame.Rows(); row++ {
					existing.AppendRow(frame.Fields[0].At(row), frame.Fields[1].At(row))
				}
				existing.Meta.Notices = append(existing.Meta.Notices, frame.Meta.Notices...)
			} else {
				frame.Meta.Type = data.FrameTypeTimeSeriesMulti
				if frame.Fields[0].Config == nil {
					frame.Fields[0].Config = &data.FieldConfig{}
				}
				frame.Fields[0].Config.Interval = float64(parts[i].Step.Milliseconds())
				series[key] = append(series[key], frame)
				merged.Frames = append(merged.Frames, frame)
			}
		}
	}
	for _, frame := range merged.Frames {
		frame.Meta.ExecutedQueryString = strings.Join(executed, "\n")
	}
	// Rates must be recomputed from total work and execution time, not summed.
	if index, ok := statIndexes[statSummaryExecTime]; ok && stats[index].Value > 0 {
		bytesRate, hasBytesRate := statIndexes[statSummaryBytesProcessedPerSecond]
		bytesTotal, hasBytesTotal := statIndexes[statSummaryTotalBytesProcessed]
		if hasBytesRate && hasBytesTotal {
			stats[bytesRate].Value = stats[bytesTotal].Value / stats[index].Value
		}
		linesRate, hasLinesRate := statIndexes[statSummaryLinesProcessedPerSecond]
		linesTotal, hasLinesTotal := statIndexes[statSummaryTotalLinesProcessed]
		if hasLinesRate && hasLinesTotal {
			stats[linesRate].Value = stats[linesTotal].Value / stats[index].Value
		}
	}
	if len(merged.Frames) > 0 {
		merged.Frames[0].Meta.Stats = stats
	}
	return merged
}

// splitLogsVolumeQuery partitions [Start, End) into disjoint count windows.
// Only the interior uses query_range so Loki's step alignment cannot expand
// either partial edge. The interior remains aligned for result caching.
func splitLogsVolumeQuery(query lokiQuery) ([]lokiQuery, error) {
	if query.Step < time.Millisecond {
		return nil, fmt.Errorf("logs volume step must be at least one millisecond")
	}
	if !query.End.After(query.Start) {
		return nil, fmt.Errorf("logs volume end must be after start")
	}
	// api.go serializes the HTTP step parameter in whole milliseconds.
	// Use the same precision when calculating bucket boundaries and lookbacks.
	query.Step = query.Step.Truncate(time.Millisecond)
	parts := make([]lokiQuery, 0, 3)
	start := query.Start
	alignedStart := alignLogsVolumeTime(start, query.Step)
	if !start.Equal(alignedStart) {
		end := alignedStart.Add(query.Step)
		if end.After(query.End) {
			end = query.End
		}
		part, err := logsVolumeInstantPart(query, end, end.Sub(start))
		if err != nil {
			return nil, err
		}
		parts = append(parts, part)
		start = end
	}
	alignedEnd := alignLogsVolumeTime(query.End, query.Step)
	if start.Before(alignedEnd) {
		// Evaluations mark bucket ends: the first full lookback starts at
		// start, so its evaluation must be one step later.
		part, err := logsVolumeRangePart(query, start.Add(query.Step), alignedEnd)
		if err != nil {
			return nil, err
		}
		parts = append(parts, part)
		start = alignedEnd
	}
	if start.Before(query.End) {
		part, err := logsVolumeInstantPart(query, query.End, query.End.Sub(start))
		if err != nil {
			return nil, err
		}
		parts = append(parts, part)
	}
	return parts, nil
}

func logsVolumeInstantPart(query lokiQuery, evaluationTime time.Time, lookback time.Duration) (lokiQuery, error) {
	expression, err := logsVolumeExpression(query.Expr, lookback)
	if err != nil {
		return lokiQuery{}, err
	}
	query.Expr = expression
	// The instant endpoint uses End as its time parameter and has no start.
	query.Start = time.Time{}
	query.End = evaluationTime
	query.QueryType = QueryTypeInstant
	return query, nil
}

func logsVolumeRangePart(query lokiQuery, start, end time.Time) (lokiQuery, error) {
	expression, err := logsVolumeExpression(query.Expr, query.Step)
	if err != nil {
		return lokiQuery{}, err
	}
	query.Expr = expression
	query.Start, query.End = start, end
	query.QueryType = QueryTypeRange
	return query, nil
}

func logsVolumeExpression(expression string, window time.Duration) (string, error) {
	if window%time.Millisecond != 0 {
		return "", fmt.Errorf("logs volume bucket duration must use millisecond precision")
	}
	expr, err := syntax.ParseExpr(expression)
	if err != nil {
		return "", fmt.Errorf("parse logs volume query: %w", err)
	}
	found := false
	expr.Walk(func(node syntax.Expr) bool {
		if aggregation, ok := node.(*syntax.RangeAggregationExpr); ok && aggregation.Operation == syntax.OpRangeTypeCount {
			aggregation.Left.Interval = window
			// Shift coverage from (start, end] to [start, end) without changing
			// the lookback duration or the aligned evaluation timestamps.
			aggregation.Left.Offset += time.Nanosecond
			found = true
		}
		return true
	})
	if !found {
		return "", fmt.Errorf("logs volume query must contain count_over_time")
	}
	return expr.String(), nil
}

// alignLogsVolumeTime matches Loki's queryrangebase.StepAlignMiddleware:
// (timestamp.UnixMilli() / stepMilliseconds) * stepMilliseconds.
// Callers validate and truncate step to at least one whole millisecond.
func alignLogsVolumeTime(timestamp time.Time, step time.Duration) time.Time {
	stepMilliseconds := step.Milliseconds()
	return time.UnixMilli(timestamp.UnixMilli() / stepMilliseconds * stepMilliseconds)
}
