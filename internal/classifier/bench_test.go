package classifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const jevReply = `{"answers":{"category":{"choice":"request","confidence":0.9},"urgency":{"score":1.8,"confidence":0.8},"needs_reply":{"noul":0.9},"phishing":{"noul":0.1}}}`

var benchEmail = Email{
	FromDomain: "broker.com", Subject: "Renewal", Importance: "high", Received: time.Unix(1_700_000_000, 0),
	Body: "Please approve the renewal of the policy today. The premium is unchanged. Let me know if you have questions.",
}

func BenchmarkJevEvaluate(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(jevReply))
	}))
	defer srv.Close()
	j := NewJev(srv.URL, "k", "m")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := j.Evaluate(context.Background(), benchEmail); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkJevPayload(b *testing.B) {
	j := NewJev("http://x", "k", "m")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := j.payload(benchEmail); err != nil {
			b.Fatal(err)
		}
	}
}
