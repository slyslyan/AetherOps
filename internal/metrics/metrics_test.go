package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

func newPromRegistry() *prometheus.Registry {
	return prometheus.NewRegistry()
}

func init() {
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
}
