package collectors

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ManagerCollector is an interface for the metrics of the Edgenexus Manager
type ManagerCollector interface {
	IncEdgeReloadCount(isEndPointUpdate bool)
	IncEdgeReloadErrors()
	UpdateLastReloadTime(ms time.Duration)
	Register(registry *prometheus.Registry) error
}

// LocalManagerMetricsCollector implements EdgeManagerCollector interface and prometheus.Collector interface
type LocalManagerMetricsCollector struct {
	// Metrics
	reloadsTotal     *prometheus.CounterVec
	reloadsError     prometheus.Counter
	lastReloadStatus prometheus.Gauge
	lastReloadTime   prometheus.Gauge
}

// NewLocalManagerMetricsCollector creates a new LocalManagerMetricsCollector
func NewLocalManagerMetricsCollector(constLabels map[string]string) *LocalManagerMetricsCollector {
	nc := &LocalManagerMetricsCollector{
		reloadsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "edge_reloads_total",
				Namespace:   metricsNamespace,
				Help:        "Number of successful Edgenexus reloads",
				ConstLabels: constLabels,
			},
			[]string{"reason"},
		),
		reloadsError: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name:        "edge_reload_errors_total",
				Namespace:   metricsNamespace,
				Help:        "Number of unsuccessful Edgenexus reloads",
				ConstLabels: constLabels,
			},
		),
		lastReloadStatus: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name:        "edge_last_reload_status",
				Namespace:   metricsNamespace,
				Help:        "Status of the last Edgenexus reload",
				ConstLabels: constLabels,
			},
		),
		lastReloadTime: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name:        "edge_last_reload_milliseconds",
				Namespace:   metricsNamespace,
				Help:        "Duration in milliseconds of the last Edgenexus reload",
				ConstLabels: constLabels,
			},
		),
	}
	nc.reloadsTotal.WithLabelValues("other")
	nc.reloadsTotal.WithLabelValues("endpoints")
	return nc
}

// IncEdgeReloadCount increments the counter of successful Edgenexus reloads and sets the last reload status to true
func (nc *LocalManagerMetricsCollector) IncEdgeReloadCount(isEndPointUpdate bool) {
	var label string
	if isEndPointUpdate {
		label = "endpoints"
	} else {
		label = "other"
	}
	nc.reloadsTotal.WithLabelValues(label).Inc()
	nc.updateLastReloadStatus(true)
}

// IncEdgeReloadErrors increments the counter of Edgenexus reload errors and sets the last reload status to false
func (nc *LocalManagerMetricsCollector) IncEdgeReloadErrors() {
	nc.reloadsError.Inc()
	nc.updateLastReloadStatus(false)
}

// updateLastReloadStatus updates the last Edgenexus reload status metric
func (nc *LocalManagerMetricsCollector) updateLastReloadStatus(up bool) {
	var status float64
	if up {
		status = 1.0
	}
	nc.lastReloadStatus.Set(status)
}

// UpdateLastReloadTime updates the last Edgenexus reload time
func (nc *LocalManagerMetricsCollector) UpdateLastReloadTime(duration time.Duration) {
	nc.lastReloadTime.Set(float64(duration / time.Millisecond))
}

// Describe implements prometheus.Collector interface Describe method
func (nc *LocalManagerMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	nc.reloadsTotal.Describe(ch)
	nc.reloadsError.Describe(ch)
	nc.lastReloadStatus.Describe(ch)
	nc.lastReloadTime.Describe(ch)
}

// Collect implements the prometheus.Collector interface Collect method
func (nc *LocalManagerMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	nc.reloadsTotal.Collect(ch)
	nc.reloadsError.Collect(ch)
	nc.lastReloadStatus.Collect(ch)
	nc.lastReloadTime.Collect(ch)
}

// Register registers all the metrics of the collector
func (nc *LocalManagerMetricsCollector) Register(registry *prometheus.Registry) error {
	return registry.Register(nc)
}

// ManagerFakeCollector is a fake collector that will implement ManagerCollector interface
type ManagerFakeCollector struct{}

// NewManagerFakeCollector creates a fake collector that implements ManagerCollector interface
func NewManagerFakeCollector() *ManagerFakeCollector {
	return &ManagerFakeCollector{}
}

// Register implements a fake Register
func (nc *ManagerFakeCollector) Register(registry *prometheus.Registry) error { return nil }

// IncEdgeReloadCount implements a fake IncEdgeReloadCount
func (nc *ManagerFakeCollector) IncEdgeReloadCount(isEndPointUpdate bool) {}

// IncEdgeReloadErrors implements a fake IncEdgeReloadErrors
func (nc *ManagerFakeCollector) IncEdgeReloadErrors() {}

// UpdateLastReloadTime implements a fake UpdateLastReloadTime
func (nc *ManagerFakeCollector) UpdateLastReloadTime(ms time.Duration) {}