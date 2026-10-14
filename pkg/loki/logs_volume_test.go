package loki

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/tracing"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/loki/v3/pkg/logql/syntax"
	"github.com/stretchr/testify/require"
)

func TestLogsVolumeRequestsAndMerge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		require.Equal(t, "Source=logvolhist", req.Header.Get("X-Query-Tags"))
		require.Contains(t, req.URL.Query().Get("query"), "offset 1ns")
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/loki/api/v1/query_range":
			require.Equal(t, "120000000000", req.URL.Query().Get("start"))
			require.Equal(t, "180000000000", req.URL.Query().Get("end"))
			require.Equal(t, "60000ms", req.URL.Query().Get("step"))
			require.Contains(t, req.URL.Query().Get("query"), "[1m]")
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"level":"info"},"values":[[120,"2"],[180,"3"]]}]}}`)
		case "/loki/api/v1/query":
			require.Contains(t, req.URL.Query().Get("query"), "[30s]")
			if req.URL.Query().Get("time") == "60000000000" {
				fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"level":"info"},"value":[60,"1"]},{"metric":{"level":"error"},"value":[60,"5"]}]}}`)
			} else {
				require.Equal(t, "210000000000", req.URL.Query().Get("time"))
				fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"level":"info"},"value":[210,"4"]},{"metric":{"level":"warn"},"value":[210,"6"]}]}}`)
			}
		default:
			t.Errorf("unexpected endpoint %s", req.URL.Path)
		}
	}))
	defer server.Close()
	plog := backend.NewLoggerWith("logger", "test")
	api := newLokiAPI(server.Client(), server.URL, plog, tracing.DefaultTracer())
	query := lokiQuery{Expr: `sum by (level) (count_over_time({app="test"}[1m]))`, QueryType: QueryTypeRange, SupportingQueryType: SupportingQueryLogsVolume, Start: time.Unix(30, 0), End: time.Unix(210, 0), Step: time.Minute}
	result, err := runQuery(context.Background(), api, &query, ResponseOpts{}, plog)
	require.NoError(t, err)
	require.NoError(t, result.Error)
	require.Len(t, result.Frames, 3)
	for _, frame := range result.Frames {
		require.Equal(t, data.FrameTypeTimeSeriesMulti, frame.Meta.Type)
		require.Equal(t, float64(60000), frame.Fields[0].Config.Interval)
		require.Contains(t, frame.Meta.ExecutedQueryString, "[30s]")
		if frame.Fields[1].Labels["level"] == "info" {
			require.Equal(t, 4, frame.Rows())
			for i, timestamp := range []int64{60, 120, 180, 210} {
				require.Equal(t, time.Unix(timestamp, 0).UnixMilli(), frame.Fields[0].At(i).(time.Time).UnixMilli())
				require.Equal(t, float64(i+1), frame.Fields[1].At(i))
			}
		} else {
			require.Equal(t, 1, frame.Rows())
		}
	}
}

func TestLogsVolumeLeavesOtherSupportingQueriesUnchanged(t *testing.T) {
	for _, supporting := range []SupportingQueryType{SupportingQueryNone, SupportingQueryLogsSample, SupportingQueryDataSample, SupportingQueryInfiniteScroll, "explore"} {
		t.Run(string(supporting), func(t *testing.T) {
			calls := 0
			api := makeMockedAPI(200, "application/json", []byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`), func(req *http.Request) {
				calls++
				require.Equal(t, `sum(count_over_time({app="test"}[1m]))`, req.URL.Query().Get("query"))
				require.Equal(t, "30000000000", req.URL.Query().Get("start"))
				require.Equal(t, "210000000000", req.URL.Query().Get("end"))
			})
			query := lokiQuery{Expr: `sum(count_over_time({app="test"}[1m]))`, QueryType: QueryTypeRange, SupportingQueryType: supporting, Start: time.Unix(30, 0), End: time.Unix(210, 0), Step: time.Minute}
			_, err := runQuery(context.Background(), api, &query, ResponseOpts{}, backend.NewLoggerWith("logger", "test"))
			require.NoError(t, err)
			require.Equal(t, 1, calls)
		})
	}
}

func TestLogsVolumeLeavesDirectInstantQueriesUnchanged(t *testing.T) {
	calls := 0
	api := makeMockedAPI(200, "application/json", []byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`), func(req *http.Request) {
		calls++
		require.Equal(t, "/loki/api/v1/query", req.URL.Path)
		require.Equal(t, "210000000000", req.URL.Query().Get("time"))
		require.Equal(t, `sum(count_over_time({app="test"}[3m]))`, req.URL.Query().Get("query"))
	})
	query := lokiQuery{Expr: `sum(count_over_time({app="test"}[3m]))`, QueryType: QueryTypeInstant, SupportingQueryType: SupportingQueryLogsVolume, Start: time.Unix(30, 0), End: time.Unix(210, 0), Step: time.Minute}
	_, err := runQuery(context.Background(), api, &query, ResponseOpts{}, backend.NewLoggerWith("logger", "test"))
	require.NoError(t, err)
	require.Equal(t, 1, calls)
}

func TestLogsVolumePartFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("time") == "210000000000" {
			http.Error(w, "edge query failed", http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[60,"1"]}]}}`)
	}))
	defer server.Close()
	plog := backend.NewLoggerWith("logger", "test")
	api := newLokiAPI(server.Client(), server.URL, plog, tracing.DefaultTracer())
	query := lokiQuery{Expr: `sum(count_over_time({app="test"}[1m]))`, QueryType: QueryTypeRange, SupportingQueryType: SupportingQueryLogsVolume, Start: time.Unix(30, 0), End: time.Unix(210, 0), Step: time.Minute}
	result, err := runQuery(context.Background(), api, &query, ResponseOpts{}, plog)
	require.NoError(t, err)
	require.ErrorContains(t, result.Error, "edge query failed")
	require.Equal(t, backend.Status(http.StatusTooManyRequests), result.Status)
	require.Empty(t, result.Frames)
}

func TestLogsVolumeMergeKeepsFingerprintCollisionsSeparate(t *testing.T) {
	// Real collision in data.Labels.Fingerprint (64-bit FNV-1). Both label
	// values are printable ASCII; no invalid UTF-8 or mocked hash is involved.
	first := data.Labels{"level": "reference"}
	second := data.Labels{"level": "vP&(Q2;qZ&Zx"}
	require.False(t, first.Equals(second))
	require.Equal(t, data.Fingerprint(0x893da6e08f14b022), first.Fingerprint())
	require.Equal(t, first.Fingerprint(), second.Fingerprint())

	makeResult := func(labels data.Labels, timestamp int64, count float64) *backend.DataResponse {
		frame := data.NewFrame("", data.NewField("Time", nil, []time.Time{time.Unix(timestamp, 0)}), data.NewField("Value", labels, []float64{count}))
		frame.Meta = &data.FrameMeta{}
		return &backend.DataResponse{Frames: data.Frames{frame}}
	}
	merged := mergeLogsVolumeResults(
		[]lokiQuery{{Step: time.Minute}, {Step: time.Minute}, {Step: time.Minute}},
		[]*backend.DataResponse{makeResult(first, 60, 1), makeResult(second, 120, 2), makeResult(first.Copy(), 180, 3)},
	)
	require.Len(t, merged.Frames, 2, "different labels must not merge even if their fingerprints match")
	require.Equal(t, first, merged.Frames[0].Fields[1].Labels)
	require.Equal(t, 2, merged.Frames[0].Rows(), "identical labels still merge within a collision bucket")
	require.Equal(t, float64(1), merged.Frames[0].Fields[1].At(0))
	require.Equal(t, float64(3), merged.Frames[0].Fields[1].At(1))
	require.Equal(t, second, merged.Frames[1].Fields[1].Labels)
	require.Equal(t, 1, merged.Frames[1].Rows())
	require.Equal(t, float64(2), merged.Frames[1].Fields[1].At(0))
}

func TestLogsVolumeStatistics(t *testing.T) {
	makeResult := func(timestamp int64, count, bytes, lines, seconds float64) *backend.DataResponse {
		frame := data.NewFrame("", data.NewField("Time", nil, []time.Time{time.Unix(timestamp, 0)}), data.NewField("Value", nil, []float64{count}))
		frame.Meta = &data.FrameMeta{Stats: []data.QueryStat{
			makeStat(statSummaryTotalBytesProcessed, bytes, "decbytes"),
			makeStat(statSummaryExecTime, seconds, "s"),
			makeStat(statSummaryBytesProcessedPerSecond, bytes/seconds, "Bps"),
			makeStat(statSummaryTotalLinesProcessed, lines, ""),
			makeStat(statSummaryLinesProcessedPerSecond, lines/seconds, ""),
		}}
		return &backend.DataResponse{Frames: data.Frames{frame}}
	}
	merged := mergeLogsVolumeResults([]lokiQuery{{Step: time.Minute}, {Step: time.Minute}}, []*backend.DataResponse{makeResult(60, 1, 100, 1000, 1), makeResult(120, 2, 500, 5000, 2)})
	require.Len(t, merged.Frames, 1)
	require.Equal(t, 2, merged.Frames[0].Rows())
	stats := merged.Frames[0].Meta.Stats
	require.Len(t, stats, 5)
	require.Equal(t, float64(600), stats[0].Value)
	require.Equal(t, float64(3), stats[1].Value)
	require.Equal(t, float64(200), stats[2].Value)
	// Processing statistics describe scanned input, not the histogram's count of 3.
	require.Equal(t, float64(6000), stats[3].Value)
	require.Equal(t, float64(2000), stats[4].Value)
}

func FuzzLogsVolumeCoverage(f *testing.F) {
	f.Add(uint32(30_000), uint32(180_000), uint32(60_000))
	f.Add(uint32(123), uint32(866), uint32(100))
	f.Fuzz(func(t *testing.T, startMs, lengthMs, stepMs uint32) {
		step := time.Duration(stepMs%60_000+1) * time.Millisecond
		start := time.UnixMilli(int64(startMs))
		end := start.Add(time.Duration(lengthMs%600_000+1) * time.Millisecond)
		parts, err := splitLogsVolumeQuery(lokiQuery{Expr: `sum(count_over_time({app="test"}[1m]))`, Start: start, End: end, Step: step})
		require.NoError(t, err)
		require.LessOrEqual(t, len(parts), 3)
		coveredUntil := start
		for _, part := range parts {
			expr, err := syntax.ParseExpr(part.Expr)
			require.NoError(t, err)
			var window time.Duration
			expr.Walk(func(node syntax.Expr) bool {
				if e, ok := node.(*syntax.LogRangeExpr); ok {
					window = e.Interval
					require.Equal(t, time.Nanosecond, e.Offset)
				}
				return true
			})
			firstEvaluation := part.End
			if part.QueryType == QueryTypeRange {
				firstEvaluation = part.Start
				require.Zero(t, part.Start.UnixMilli()%step.Milliseconds())
				require.Zero(t, part.End.UnixMilli()%step.Milliseconds())
				require.Equal(t, step, window)
			}
			require.Equal(t, coveredUntil.UnixNano(), firstEvaluation.Add(-window).UnixNano(), strconv.Itoa(len(parts)))
			require.True(t, part.End.After(coveredUntil))
			coveredUntil = part.End
		}
		require.Equal(t, end.UnixNano(), coveredUntil.UnixNano())
	})
}

func TestSplitLogsVolumeQuery(t *testing.T) {
	for _, tc := range []struct {
		name          string
		start, end    int64
		types         []QueryType
		ends, windows []int64
	}{
		{"both edges", 30, 1830, []QueryType{QueryTypeInstant, QueryTypeRange, QueryTypeInstant}, []int64{60, 1800, 1830}, []int64{30, 60, 30}},
		{"aligned", 0, 1800, []QueryType{QueryTypeRange}, []int64{1800}, []int64{60}},
		{"left edge", 30, 1800, []QueryType{QueryTypeInstant, QueryTypeRange}, []int64{60, 1800}, []int64{30, 60}},
		{"right edge", 0, 1830, []QueryType{QueryTypeRange, QueryTypeInstant}, []int64{1800, 1830}, []int64{60, 30}},
		{"within one bucket", 10, 20, []QueryType{QueryTypeInstant}, []int64{20}, []int64{10}},
		{"crosses one boundary", 50, 70, []QueryType{QueryTypeInstant, QueryTypeInstant}, []int64{60, 70}, []int64{10, 10}},
		{"partial then one full bucket", 30, 120, []QueryType{QueryTypeInstant, QueryTypeRange}, []int64{60, 120}, []int64{30, 60}},
		{"partial ending on boundary", 30, 60, []QueryType{QueryTypeInstant}, []int64{60}, []int64{30}},
		{"one full bucket", 60, 120, []QueryType{QueryTypeRange}, []int64{120}, []int64{60}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := lokiQuery{Expr: `sum by (level) (count_over_time({app="test"} |= "[1m]" [1m]))`, Start: time.Unix(tc.start, 0), End: time.Unix(tc.end, 0), Step: time.Minute, RefID: "A", SupportingQueryType: SupportingQueryLogsVolume}
			parts, err := splitLogsVolumeQuery(query)
			require.NoError(t, err)
			require.Len(t, parts, len(tc.types))
			coveredUntil := query.Start
			for i, part := range parts {
				require.Equal(t, tc.types[i], part.QueryType)
				require.Equal(t, time.Unix(tc.ends[i], 0), part.End)
				require.Equal(t, query.RefID, part.RefID)
				require.Equal(t, query.SupportingQueryType, part.SupportingQueryType)
				require.Contains(t, part.Expr, `|= "[1m]"`)
				expr, err := syntax.ParseExpr(part.Expr)
				require.NoError(t, err)
				expr.Walk(func(node syntax.Expr) bool {
					if window, ok := node.(*syntax.LogRangeExpr); ok {
						require.Equal(t, time.Duration(tc.windows[i])*time.Second, window.Interval)
						require.Equal(t, time.Nanosecond, window.Offset)
						if part.QueryType == QueryTypeRange {
							require.Equal(t, coveredUntil, part.Start.Add(-window.Interval))
						} else {
							require.Equal(t, coveredUntil, part.End.Add(-window.Interval))
						}
					}
					return true
				})
				coveredUntil = part.End
			}
			require.Equal(t, query.End, coveredUntil)
		})
	}
}

func TestLogsVolumePreservesExistingOffset(t *testing.T) {
	query := lokiQuery{Expr: `sum(count_over_time({app="test"}[1m] offset 1s))`, Start: time.Unix(30, 0), End: time.Unix(210, 0), Step: time.Minute}
	parts, err := splitLogsVolumeQuery(query)
	require.NoError(t, err)
	require.Len(t, parts, 3)
	for _, part := range parts {
		expr, err := syntax.ParseExpr(part.Expr)
		require.NoError(t, err)
		expr.Walk(func(node syntax.Expr) bool {
			if window, ok := node.(*syntax.LogRangeExpr); ok {
				require.Equal(t, time.Second+time.Nanosecond, window.Offset)
			}
			return true
		})
	}
}
