package loki

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/loki/v3/pkg/logql/syntax"
	"github.com/stretchr/testify/require"
)

// These fixtures are shared with Loki's logs-volume-boundary-tests workspace.
// The responses were produced by its actual LogQL engine at revision
// 7be2bb61a18df309321d351305e4b3066f0a3445, using StepAlignMiddleware and
// MockQuerier storage and Loki's HTTP response encoder. Execution statistics
// are zeroed for deterministic recordings. Reproduce with:
//
//	VOLUME_BOUNDARY_RESULTS=testdata/logs_volume_boundary_results.json \
//	  CGO_ENABLED=0 go test ./pkg/logql -run '^TestLogsVolume' -count=1 -v
//
// Both offset and non-offset requests have recorded responses. The test must
// fail on the actual count discrepancy, not a missing mock or transport error.
// The recorded offset control proves that the fixtures and merge
// work before the datasource starts adding the offset itself.
func TestLogsVolumeReplayLokiBoundaryCorpus(t *testing.T) {
	var corpus struct {
		BaseTime  string `json:"base_time"`
		Selector  string `json:"selector"`
		Scenarios []struct {
			Name         string         `json:"name"`
			StartNS      string         `json:"start_ns"`
			EndNS        string         `json:"end_ns"`
			StepNS       string         `json:"step_ns"`
			ExpectedLogs map[string]int `json:"expected_logs"`
		} `json:"scenarios"`
	}
	readVolumeFixture(t, "testdata/logs_volume_boundaries.json", &corpus)
	var reports []volumeCorpusReport
	readVolumeFixture(t, "testdata/logs_volume_boundary_results.json", &reports)
	require.Len(t, reports, len(corpus.Scenarios))
	base, err := time.Parse(time.RFC3339Nano, corpus.BaseTime)
	require.NoError(t, err)
	for i, scenario := range corpus.Scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			report := reports[i]
			require.Equal(t, scenario.Name, report.Scenario)
			require.Equal(t, scenario.ExpectedLogs, report.Logs)
			require.Equal(t, scenario.ExpectedLogs, report.OffsetCounts)
			require.Len(t, report.OffsetExchanges, len(report.Exchanges))
			for _, replayOffset := range []bool{false, true} {
				name := "datasource_adds_offset"
				if replayOffset {
					name = "recorded_offset_control"
				}
				t.Run(name, func(t *testing.T) {
					transport := &volumeCorpusTransport{responses: map[string]json.RawMessage{}, calls: map[string]int{}}
					for _, exchanges := range [][]volumeCorpusExchange{report.Exchanges, report.OffsetExchanges} {
						for _, exchange := range exchanges {
							key, err := volumeCorpusKey(exchange.Query, exchange.Part.Start, exchange.Part.End, exchange.Part.Step)
							require.NoError(t, err)
							transport.responses[key] = exchange.Response
						}
					}
					api := makeMockedAPI(200, "application/json", nil, nil)
					api.client.Transport = transport
					query := lokiQuery{
						Expr:                fmt.Sprintf("sum by (level) (count_over_time(%s[1m]))", corpus.Selector),
						Start:               base.Add(volumeCorpusDuration(t, scenario.StartNS)),
						End:                 base.Add(volumeCorpusDuration(t, scenario.EndNS)),
						Step:                volumeCorpusDuration(t, scenario.StepNS),
						QueryType:           QueryTypeRange,
						SupportingQueryType: SupportingQueryLogsVolume,
					}
					var result *backend.DataResponse
					var err error
					plog := backend.NewLoggerWith("logger", "test")
					if replayOffset {
						var parts []lokiQuery
						var responses []*backend.DataResponse
						for _, exchange := range report.OffsetExchanges {
							part := query
							part.Expr, part.Start, part.End = exchange.Query, exchange.Part.Start, exchange.Part.End
							if exchange.Part.Step == 0 {
								part.QueryType = QueryTypeInstant
							}
							response, queryErr := runSingleQuery(context.Background(), api, &part, ResponseOpts{}, plog)
							require.NoError(t, queryErr)
							require.NoError(t, response.Error)
							parts = append(parts, part)
							responses = append(responses, response)
						}
						result = mergeLogsVolumeResults(parts, responses)
					} else {
						result, err = runQuery(context.Background(), api, &query, ResponseOpts{}, plog)
					}
					require.NoError(t, err)
					require.NoError(t, result.Error)
					counts := map[string]int{}
					for _, frame := range result.Frames {
						level := frame.Fields[1].Labels["level"]
						for row := 0; row < frame.Rows(); row++ {
							value := int(frame.Fields[1].At(row).(float64))
							if value != 0 {
								counts[level] += value
							}
						}
					}
					require.Len(t, transport.calls, len(report.Exchanges))
					for _, calls := range transport.calls {
						require.Equal(t, 1, calls)
					}
					require.Equal(t, scenario.ExpectedLogs, counts, "histogram must match [start,end) log counts per level")
				})
			}
		})
	}
}

// Nanosecond lookback durations remain unsupported; the working correction
// uses offset 1ns instead, as verified by the round-trip test below.
func TestLogsVolumeBoundaryCorpusPrecisionLimitation(t *testing.T) {
	var reports []volumeCorpusReport
	readVolumeFixture(t, "testdata/logs_volume_boundary_results.json", &reports)
	for _, report := range reports {
		t.Run(report.Scenario, func(t *testing.T) {
			require.Equal(t, report.Logs, report.AdjustedAST)
			for _, part := range report.AdjustedParts {
				_, err := syntax.ParseExpr(fmt.Sprintf(`count_over_time({app="volume-boundary"}[%s])`, part.Window))
				if part.Window%time.Millisecond != 0 {
					require.Error(t, err, "nanosecond lookback is not supported by Loki")
				} else {
					require.NoError(t, err)
				}
			}
		})
	}
}

type volumeCorpusPart struct {
	Start  time.Time     `json:"start"`
	End    time.Time     `json:"end"`
	Step   time.Duration `json:"step_ns"`
	Window time.Duration `json:"window_ns"`
}

func TestLogsVolumeNanosecondOffsetRoundTrip(t *testing.T) {
	for _, window := range []string{"1ms", "100ms", "30s", "1m"} {
		t.Run(window, func(t *testing.T) {
			expr, err := syntax.ParseExpr(fmt.Sprintf(`sum by (level) (count_over_time({app="volume-boundary"}[%s] offset 1ns))`, window))
			require.NoError(t, err)
			reparsed, err := syntax.ParseExpr(expr.String())
			require.NoError(t, err)
			reparsed.Walk(func(node syntax.Expr) bool {
				if r, ok := node.(*syntax.LogRangeExpr); ok {
					require.Equal(t, time.Nanosecond, r.Offset)
				}
				return true
			})
		})
	}
}

type volumeCorpusReport struct {
	Scenario        string                 `json:"scenario"`
	Logs            map[string]int         `json:"logs"`
	OffsetCounts    map[string]int         `json:"offset_1ns_wire"`
	AdjustedAST     map[string]int         `json:"adjusted_ast_engine_only"`
	AdjustedParts   []volumeCorpusPart     `json:"adjusted_parts"`
	Exchanges       []volumeCorpusExchange `json:"split_exchanges"`
	OffsetExchanges []volumeCorpusExchange `json:"offset_exchanges"`
}

type volumeCorpusExchange struct {
	Part     volumeCorpusPart `json:"part"`
	Query    string           `json:"query"`
	Response json.RawMessage  `json:"response"`
}

type volumeCorpusTransport struct {
	mu        sync.Mutex
	responses map[string]json.RawMessage
	calls     map[string]int
}

func (transport *volumeCorpusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("X-Query-Tags") != "Source=logvolhist" {
		return nil, fmt.Errorf("missing logs volume query tag")
	}
	values := req.URL.Query()
	parseTime := func(key string) (time.Time, error) {
		ns, err := strconv.ParseInt(values.Get(key), 10, 64)
		return time.Unix(0, ns), err
	}
	var start, end time.Time
	var step time.Duration
	var err error
	switch req.URL.Path {
	case "/loki/api/v1/query":
		end, err = parseTime("time")
		start = end
	case "/loki/api/v1/query_range":
		start, err = parseTime("start")
		if err != nil {
			return nil, err
		}
		end, err = parseTime("end")
		if err != nil {
			return nil, err
		}
		step, err = time.ParseDuration(values.Get("step"))
	default:
		return nil, fmt.Errorf("unexpected endpoint %s", req.URL.Path)
	}
	if err != nil {
		return nil, err
	}
	key, err := volumeCorpusKey(values.Get("query"), start, end, step)
	if err != nil {
		return nil, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	body, ok := transport.responses[key]
	if !ok {
		return nil, fmt.Errorf("request has no Loki-recorded response: %s", key)
	}
	transport.calls[key]++
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func volumeCorpusKey(query string, start, end time.Time, step time.Duration) (string, error) {
	expr, err := syntax.ParseExpr(query)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s|%d|%d|%d", expr.String(), start.UnixNano(), end.UnixNano(), step), nil
}

func readVolumeFixture(t *testing.T, filename string, target any) {
	t.Helper()
	raw, err := os.ReadFile(filename)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, target))
}

func volumeCorpusDuration(t *testing.T, value string) time.Duration {
	t.Helper()
	ns, err := strconv.ParseInt(value, 10, 64)
	require.NoError(t, err)
	return time.Duration(ns)
}
