/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package monitoring

import (
	"context"
	"net/http"
	"net/url"

	"github.com/gravitational/satellite/agent/health"
	"github.com/gravitational/trace"

	"github.com/gravitational/roundtrip"
	log "github.com/sirupsen/logrus"
)

// NewUDPChecker returns a new udp checker
func NewUDPChecker() *udpChecker {
	return &udpChecker{}
}

// udpChecker validates that udp network communication between peers.
type udpChecker struct{}

// Name returns this checker name
// Implements health.Checker
func (c *udpChecker) Name() string {
	return udpCheckerID
}

// Check ...
// Implements health.Checker
func (c *udpChecker) Check(ctx context.Context, reporter health.Reporter) {
	const nethealthServiceAddr = "nethealth.monitoring.svc.cluster.local:9801/metrics"
	client, err := getNethealthClient()
	if err != nil {
		log.WithError(err).Warn("Failed to get nethealth client.")
	}
	resp, err := client.Get(ctx, nethealthServiceAddr, url.Values{})
	if err != nil {
		log.WithError(err).Warn("Failed to get nethealth metrics.")
	}
	data := string(resp.Bytes())
	log.WithField("data", data).Info("Nethealth metrics...")
	reporter.Add(NewProbeFromErr(c.Name(), "failed nethealth test", trace.Wrap(err)))
}

func getNethealthClient() (*roundtrip.Client, error) {
	const nethealthServiceAddr = "nethealth.monitoring.svc.cluster.local:9801"
	return roundtrip.NewClient(nethealthServiceAddr, "/metrics", roundtrip.HTTPClient(&http.Client{}))
}

const (
	udpCheckerID = "udp-checker"
)
