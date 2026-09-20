package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xsaveopt/minecraft-ebpf/internal/loader"
)

const missingPinPath = "testdata/no-such-pin-directory"

func serve(t *testing.T, h http.HandlerFunc, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func decodeJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out
}

func requireJSONResponse(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q, want application/json", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control %q, want no-store", cc)
	}
}

func TestWriteJSONSetsHeadersAndLeavesHTMLUnescaped(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, map[string]string{"motd": "a<b&c"})
	requireJSONResponse(t, rec)
	if !strings.Contains(rec.Body.String(), `"a<b&c"`) {
		t.Fatalf("body %q escaped HTML, want it verbatim", rec.Body.String())
	}
}

func TestTimestampEndpointReportsWholeSecondsOfAge(t *testing.T) {
	now := bootNS()
	m := newFakeMap(8)
	m.put(t, "10.0.0.1", now-5_500_000_000)
	m.put(t, "10.0.0.2", now+2_000_000_000)

	rec := serve(t, handleTimestampMap(m), "/api/whitelist")
	requireJSONResponse(t, rec)

	got := decodeJSON[[]timestampEntry](t, rec)
	want := []timestampEntry{
		{IP: "10.0.0.1", AgeSeconds: 5},
		{IP: "10.0.0.2", AgeSeconds: 0},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCountEndpointReportsRawCounts(t *testing.T) {
	m := newFakeMap(8)
	m.put(t, "192.168.1.7", uint64(9))

	rec := serve(t, handleCountMap(m), "/api/open-count")
	requireJSONResponse(t, rec)

	got := decodeJSON[[]countEntry](t, rec)
	if len(got) != 1 || got[0] != (countEntry{IP: "192.168.1.7", Count: 9}) {
		t.Fatalf("got %+v, want one entry 192.168.1.7 count=9", got)
	}
}

func TestBlacklistEndpointOmitsIPsWhoseBanHasExpired(t *testing.T) {
	now := bootNS()
	m := newFakeMap(24)
	m.put(t, "10.0.0.1", fakeHealth{
		Anomalies:        42,
		WindowStartNS:    now - 9_500_000_000,
		BlacklistUntilNS: now + 30_500_000_000,
	})
	m.put(t, "10.0.0.2", fakeHealth{
		Anomalies:        3,
		WindowStartNS:    now - 1_500_000_000,
		BlacklistUntilNS: now - 1_000_000_000,
	})

	rec := serve(t, handleBlacklist(m), "/api/blacklist")
	requireJSONResponse(t, rec)

	got := decodeJSON[[]blacklistEntry](t, rec)
	want := blacklistEntry{
		IP:                        "10.0.0.1",
		Anomalies:                 42,
		WindowAgeSeconds:          9,
		BlacklistRemainingSeconds: 30,
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want only the blacklisted one: %+v", len(got), got)
	}
	if got[0] != want {
		t.Fatalf("got %+v, want %+v", got[0], want)
	}
}

func TestDropHistoryEndpointNamesEveryReasonSlot(t *testing.T) {
	now := bootNS()
	var counts [10]uint64
	for i := range counts {
		counts[i] = uint64(i + 1)
	}
	m := newFakeMap(96)
	m.put(t, "203.0.113.9", fakeDropHistory{
		FirstDropNS: now - 60_500_000_000,
		LastDropNS:  now - 2_500_000_000,
		Counts:      counts,
	})

	rec := serve(t, handleDropHistory(m), "/api/drop-history")
	requireJSONResponse(t, rec)

	got := decodeJSON[[]dropHistoryEntry](t, rec)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(got), got)
	}
	e := got[0]
	if e.IP != "203.0.113.9" || e.FirstDropAgeSeconds != 60 || e.LastDropAgeSeconds != 2 {
		t.Errorf("got ip=%s first=%d last=%d, want 203.0.113.9 60 2", e.IP, e.FirstDropAgeSeconds, e.LastDropAgeSeconds)
	}
	if e.Total != 55 {
		t.Errorf("total = %d, want 55", e.Total)
	}
	if len(e.ByReason) != len(dropReasonNames) {
		t.Fatalf("by_reason has %d keys, want %d: %v", len(e.ByReason), len(dropReasonNames), e.ByReason)
	}
	for i, name := range dropReasonNames {
		if e.ByReason[name] != uint64(i+1) {
			t.Errorf("by_reason[%s] = %d, want %d", name, e.ByReason[name], i+1)
		}
	}
}

func TestDropHistoryEndpointSkipsZeroedReasons(t *testing.T) {
	m := newFakeMap(96)
	m.put(t, "203.0.113.9", fakeDropHistory{Counts: [10]uint64{5: 4}})

	rec := serve(t, handleDropHistory(m), "/api/drop-history")
	got := decodeJSON[[]dropHistoryEntry](t, rec)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if len(got[0].ByReason) != 1 || got[0].ByReason["malformed_handshake"] != 4 {
		t.Fatalf("by_reason = %v, want only malformed_handshake=4", got[0].ByReason)
	}
}

func TestHealthEndpointHidesUnbannedIPsUnlessAllIsRequested(t *testing.T) {
	now := bootNS()
	m := newFakeMap(24)
	m.put(t, "10.0.0.1", fakeHealth{
		Anomalies:        42,
		WindowStartNS:    now - 9_500_000_000,
		BlacklistUntilNS: now + 30_500_000_000,
	})
	m.put(t, "10.0.0.2", fakeHealth{
		Anomalies:     3,
		WindowStartNS: now - 1_500_000_000,
	})

	rec := serve(t, handleHealth(m), "/api/health")
	requireJSONResponse(t, rec)
	got := decodeJSON[[]map[string]any](t, rec)
	if len(got) != 1 || got[0]["ip"] != "10.0.0.1" {
		t.Fatalf("default view = %v, want only 10.0.0.1", got)
	}
	if got[0]["blacklisted"] != true || got[0]["blacklist_remaining_seconds"] != float64(30) {
		t.Fatalf("blacklisted entry = %v, want blacklisted with 30s remaining", got[0])
	}
	if got[0]["anomalies"] != float64(42) || got[0]["window_age_seconds"] != float64(9) {
		t.Fatalf("blacklisted entry = %v, want anomalies=42 window_age_seconds=9", got[0])
	}

	recAll := serve(t, handleHealth(m), "/api/health?all=1")
	all := decodeJSON[[]map[string]any](t, recAll)
	if len(all) != 2 {
		t.Fatalf("?all=1 returned %d entries, want 2: %v", len(all), all)
	}
	if all[1]["blacklisted"] != false {
		t.Fatalf("second entry = %v, want blacklisted=false", all[1])
	}
	if _, ok := all[1]["blacklist_remaining_seconds"]; ok {
		t.Fatalf("second entry = %v, want no blacklist_remaining_seconds key", all[1])
	}
}

func TestMapEndpointsOnAnUnloadedDaemonAreEmptyArraysNotNull(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"timestamp":    handleTimestampMap(nil),
		"count":        handleCountMap(nil),
		"blacklist":    handleBlacklist(nil),
		"drop_history": handleDropHistory(nil),
		"health":       handleHealth(nil),
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			rec := serve(t, h, "/api/whatever")
			requireJSONResponse(t, rec)
			if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
				t.Fatalf("body = %q, want []", got)
			}
		})
	}
}

func TestIPLookupRejectsAddressesItCannotUse(t *testing.T) {
	h := handleIPLookup(&loader.Loaded{})
	cases := []struct {
		name string
		path string
		want string
	}{
		{"empty", "/api/ip/", "missing IP"},
		{"not an ip", "/api/ip/banana", "invalid IP"},
		{"ipv6", "/api/ip/2001:db8::1", "IPv4 only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(t, h, tc.path)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("body %q, want it to mention %q", rec.Body.String(), tc.want)
			}
		})
	}
}

func TestIPLookupOnAnUnloadedDaemonReportsEveryMapAsNull(t *testing.T) {
	rec := serve(t, handleIPLookup(&loader.Loaded{}), "/api/ip/10.0.0.1")
	requireJSONResponse(t, rec)

	got := decodeJSON[map[string]any](t, rec)
	if got["ip"] != "10.0.0.1" {
		t.Fatalf("ip = %v, want 10.0.0.1", got["ip"])
	}
	for _, k := range []string{
		"tcp_whitelist", "tcp_established", "tcp_syn_seen", "tcp_open_count",
		"status_ratelimit", "login_ratelimit", "syn_ratelimit", "conn_ratelimit",
		"health", "drop_history",
	} {
		v, ok := got[k]
		if !ok {
			t.Errorf("key %s missing from response", k)
			continue
		}
		if v != nil {
			t.Errorf("%s = %v, want null", k, v)
		}
	}
	if len(got) != 11 {
		t.Fatalf("response has %d keys, want 11: %v", len(got), got)
	}
}

func TestPerIPLookupHelpersShapeTheirValues(t *testing.T) {
	now := bootNS()
	key := mustIPKey(t, "10.0.0.1")

	t.Run("timestamp", func(t *testing.T) {
		m := newFakeMap(8).put(t, "10.0.0.1", now-3_500_000_000)
		got := lookupTimestamp(m, key, now).(map[string]any)
		if got["age_seconds"] != int64(3) {
			t.Fatalf("got %v, want age_seconds 3", got)
		}
	})
	t.Run("count", func(t *testing.T) {
		m := newFakeMap(8).put(t, "10.0.0.1", uint64(4))
		got := lookupCount(m, key).(map[string]any)
		if got["count"] != uint64(4) {
			t.Fatalf("got %v, want count 4", got)
		}
	})
	t.Run("ratelimit", func(t *testing.T) {
		m := newFakeMap(16).put(t, "10.0.0.1", fakeRatelimit{Tokens: 6, LastRefillNS: now - 2_500_000_000})
		got := lookupRatelimit(m, key, now).(map[string]any)
		if got["tokens"] != uint64(6) || got["last_refill_age_seconds"] != int64(2) {
			t.Fatalf("got %v, want tokens 6 age 2", got)
		}
	})
	t.Run("conn_limit", func(t *testing.T) {
		m := newFakeMap(32).put(t, "10.0.0.1", fakeConnLimit{
			PktTokens:  11,
			PktLastNS:  now - 1_500_000_000,
			ByteTokens: 2048,
		})
		got := lookupConnLimit(m, key, now).(map[string]any)
		if got["pkt_tokens"] != uint64(11) || got["byte_tokens"] != uint64(2048) || got["last_refill_age_seconds"] != int64(1) {
			t.Fatalf("got %v, want pkt 11 byte 2048 age 1", got)
		}
	})
	t.Run("health", func(t *testing.T) {
		m := newFakeMap(24).put(t, "10.0.0.1", fakeHealth{
			Anomalies:        7,
			WindowStartNS:    now - 4_500_000_000,
			BlacklistUntilNS: now + 60_500_000_000,
		})
		got := lookupHealth(m, key, now).(map[string]any)
		if got["anomalies"] != uint32(7) || got["window_age_seconds"] != int64(4) {
			t.Fatalf("got %v, want anomalies 7 window 4", got)
		}
		if got["blacklisted"] != true || got["blacklist_remaining_seconds"] != int64(60) {
			t.Fatalf("got %v, want blacklisted with 60s left", got)
		}
	})
	t.Run("health not blacklisted", func(t *testing.T) {
		m := newFakeMap(24).put(t, "10.0.0.1", fakeHealth{Anomalies: 1, WindowStartNS: now})
		got := lookupHealth(m, key, now).(map[string]any)
		if got["blacklisted"] != false {
			t.Fatalf("got %v, want blacklisted false", got)
		}
		if _, ok := got["blacklist_remaining_seconds"]; ok {
			t.Fatalf("got %v, want no blacklist_remaining_seconds", got)
		}
	})
	t.Run("drop history", func(t *testing.T) {
		m := newFakeMap(96).put(t, "10.0.0.1", fakeDropHistory{
			FirstDropNS: now - 10_500_000_000,
			LastDropNS:  now - 500_000_000,
			Counts:      [10]uint64{0: 2, 4: 3},
		})
		got := lookupDropHistory(m, key, now).(map[string]any)
		if got["total"] != uint64(5) {
			t.Fatalf("got %v, want total 5", got)
		}
		by := got["by_reason"].(map[string]uint64)
		if len(by) != 2 || by["tcp_no_syn"] != 2 || by["login_ratelimit"] != 3 {
			t.Fatalf("by_reason = %v, want tcp_no_syn 2 and login_ratelimit 3", by)
		}
		if got["first_drop_age_seconds"] != int64(10) || got["last_drop_age_seconds"] != int64(0) {
			t.Fatalf("got %v, want first 10 last 0", got)
		}
	})
}

func TestPerIPLookupHelpersReturnNilForAMissingKey(t *testing.T) {
	now := bootNS()
	absent := mustIPKey(t, "10.0.0.99")
	if got := lookupTimestamp(newFakeMap(8), absent, now); got != nil {
		t.Errorf("lookupTimestamp = %v, want nil", got)
	}
	if got := lookupCount(newFakeMap(8), absent); got != nil {
		t.Errorf("lookupCount = %v, want nil", got)
	}
	if got := lookupRatelimit(newFakeMap(16), absent, now); got != nil {
		t.Errorf("lookupRatelimit = %v, want nil", got)
	}
	if got := lookupConnLimit(newFakeMap(32), absent, now); got != nil {
		t.Errorf("lookupConnLimit = %v, want nil", got)
	}
	if got := lookupHealth(newFakeMap(24), absent, now); got != nil {
		t.Errorf("lookupHealth = %v, want nil", got)
	}
	if got := lookupDropHistory(newFakeMap(96), absent, now); got != nil {
		t.Errorf("lookupDropHistory = %v, want nil", got)
	}
}

func TestStatsEndpointOnAnUnloadedDaemonReturnsNull(t *testing.T) {
	rec := serve(t, handleStats(&loader.Loaded{}), "/api/stats")
	requireJSONResponse(t, rec)
	if got := strings.TrimSpace(rec.Body.String()); got != "null" {
		t.Fatalf("body = %q, want null", got)
	}
}

func TestMapPopulationsReportsMinusOneForEveryUnloadedMap(t *testing.T) {
	got := mapPopulations(&loader.Loaded{})
	if len(got) != 10 {
		t.Fatalf("got %d maps, want 10: %v", len(got), got)
	}
	for name, n := range got {
		if n != -1 {
			t.Errorf("%s = %d, want -1", name, n)
		}
	}
}

func TestInfoEndpointEchoesTheDaemonConfiguration(t *testing.T) {
	cfg := apiCfg{
		Loaded:  &loader.Loaded{XDPMode: "native"},
		Version: "v1.2.3",
		Iface:   "eth0",
		Port:    25565,
		PinPath: "/sys/fs/bpf/minecraft",
		Limits: apiLimits{
			StatusPerMin: 60,
			LoginBurst:   8,
			WhitelistTTL: 10 * time.Minute,
		},
	}

	rec := serve(t, handleInfo(cfg), "/api/info")
	requireJSONResponse(t, rec)

	got := decodeJSON[map[string]any](t, rec)
	if got["version"] != "v1.2.3" || got["iface"] != "eth0" || got["port"] != float64(25565) {
		t.Fatalf("got %v, want version/iface/port echoed back", got)
	}
	if got["pin_path"] != "/sys/fs/bpf/minecraft" || got["xdp_mode"] != "native" {
		t.Fatalf("got %v, want pin_path and xdp_mode echoed back", got)
	}
	attached := got["attached"].(map[string]any)
	if attached["xdp"] != false || attached["sockops"] != false {
		t.Fatalf("attached = %v, want both false", attached)
	}
	limits := got["limits"].(map[string]any)
	if limits["status_per_min"] != float64(60) || limits["login_burst"] != float64(8) {
		t.Fatalf("limits = %v, want status_per_min 60 and login_burst 8", limits)
	}
	if limits["whitelist_ttl_ns"] != float64(600_000_000_000) {
		t.Fatalf("whitelist_ttl_ns = %v, want 600000000000", limits["whitelist_ttl_ns"])
	}
	if got["counters"] != nil {
		t.Fatalf("counters = %v, want null on an unloaded daemon", got["counters"])
	}
	maps := got["maps"].(map[string]any)
	if len(maps) != 10 {
		t.Fatalf("maps = %v, want 10 entries", maps)
	}
}

func TestTopEndpointRejectsBadQueries(t *testing.T) {
	h := handleTop(apiCfg{Loaded: &loader.Loaded{}, PinPath: missingPinPath})
	cases := []struct {
		name string
		path string
		want string
	}{
		{"no map", "/api/top", "missing ?map="},
		{"unknown map", "/api/top?map=banana", "unknown map: banana"},
		{"unknown reason", "/api/top?map=drop-history&reason=banana", "unknown reason: banana"},
		{"unopenable pin path", "/api/top?map=whitelist", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(t, h, tc.path)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400; body %q", rec.Code, rec.Body.String())
			}
			if tc.want != "" && !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("body %q, want it to mention %q", rec.Body.String(), tc.want)
			}
		})
	}
}

func TestRegisteredRoutesAllAnswerWithJSON(t *testing.T) {
	mux := http.NewServeMux()
	registerAPI(mux, apiCfg{Loaded: &loader.Loaded{}, PinPath: missingPinPath})

	for _, path := range []string{
		"/api/info",
		"/api/stats",
		"/api/health",
		"/api/whitelist",
		"/api/established",
		"/api/syn-seen",
		"/api/open-count",
		"/api/blacklist",
		"/api/drop-history",
		"/api/ip/10.0.0.1",
		"/api/state",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			requireJSONResponse(t, rec)
		})
	}
}

func TestStateEndpointAdvertisesOnlyRoutesThatExist(t *testing.T) {
	mux := http.NewServeMux()
	registerAPI(mux, apiCfg{Loaded: &loader.Loaded{}, PinPath: missingPinPath})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/state", nil))
	requireJSONResponse(t, rec)

	advertised := decodeJSON[[]string](t, rec)
	if len(advertised) != 11 {
		t.Fatalf("/api/state lists %d routes, want 11: %v", len(advertised), advertised)
	}
	for _, entry := range advertised {
		path := entry
		if i := strings.IndexAny(path, "?<"); i >= 0 {
			path = path[:i]
		}
		_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, path, nil))
		if pattern == "" {
			t.Errorf("/api/state advertises %q but %q is not registered", entry, path)
		}
	}
}
