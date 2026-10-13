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
		recomputeRate := func(rate, total string) {
			rateIndex, hasRate := statIndexes[rate]
			totalIndex, hasTotal := statIndexes[total]
			if hasRate && hasTotal {
				stats[rateIndex].Value = stats[totalIndex].Value / stats[index].Value
			}
		}
		recomputeRate(statSummaryBytesProcessedPerSecond, statSummaryTotalBytesProcessed)
		recomputeRate(statSummaryLinesProcessedPerSecond, statSummaryTotalLinesProcessed)
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
	// The wire format expresses steps in whole milliseconds.
	query.Step = query.Step.Truncate(time.Millisecond)
	parts := make([]lokiQuery, 0, 3)
	start := query.Start
	alignedStart := time.Unix(0, start.UnixNano()/int64(query.Step)*int64(query.Step))
	if !start.Equal(alignedStart) {
		end := alignedStart.Add(query.Step)
		if end.After(query.End) {
			end = query.End
		}
		part, err := logsVolumePart(query, start, end, QueryTypeInstant, end.Sub(start))
		if err != nil {
			return nil, err
		}
		parts = append(parts, part)
		start = end
	}
	alignedEnd := time.Unix(0, query.End.UnixNano()/int64(query.Step)*int64(query.Step))
	if start.Before(alignedEnd) {
		part, err := logsVolumePart(query, start.Add(query.Step), alignedEnd, QueryTypeRange, query.Step)
		if err != nil {
			return nil, err
		}
		parts = append(parts, part)
		start = alignedEnd
	}
	if start.Before(query.End) {
		part, err := logsVolumePart(query, start, query.End, QueryTypeInstant, query.End.Sub(start))
		if err != nil {
			return nil, err
		}
		parts = append(parts, part)
	}
	return parts, nil
}

func logsVolumePart(query lokiQuery, start, end time.Time, queryType QueryType, window time.Duration) (lokiQuery, error) {
	if window%time.Millisecond != 0 {
		return lokiQuery{}, fmt.Errorf("logs volume bucket duration must use millisecond precision")
	}
	expr, err := syntax.ParseExpr(query.Expr)
	if err != nil {
		return lokiQuery{}, fmt.Errorf("parse logs volume query: %w", err)
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
		return lokiQuery{}, fmt.Errorf("logs volume query must contain count_over_time")
	}
	query.Expr = expr.String()
	query.Start, query.End, query.QueryType = start, end, queryType
	return query, nil
}
