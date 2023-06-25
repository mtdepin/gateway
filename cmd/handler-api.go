package cmd

import (
	"net/http"
	"sync"
	"time"

	"github.com/minio/minio/internal/config/api"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/sys"
)

type apiConfig struct {
	mu sync.RWMutex

	requestsDeadline time.Duration
	requestsPool     chan struct{}
	clusterDeadline  time.Duration
	listQuorum       int
	corsAllowOrigins []string
	// total drives per erasure set across pools.
	totalDriveCount          int
	replicationWorkers       int
	replicationFailedWorkers int
}

func (t *apiConfig) init(cfg api.Config, setDriveCounts []int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.clusterDeadline = cfg.ClusterDeadline
	t.corsAllowOrigins = cfg.CorsAllowOrigin
	for _, setDriveCount := range setDriveCounts {
		t.totalDriveCount += setDriveCount
	}

	var apiRequestsMaxPerNode int
	if cfg.RequestsMax <= 0 {
		stats, err := sys.GetStats()
		if err != nil {
			logger.LogIf(GlobalContext, err)
			// Default to 8 GiB, not critical.
			stats.TotalRAM = 8 << 30
		}
		// max requests per node is calculated as
		// total_ram / ram_per_request
		// ram_per_request is (2MiB+128KiB) * driveCount \
		//    + 2 * 10MiB (default erasure block size v1) + 2 * 1MiB (default erasure block size v2)
		apiRequestsMaxPerNode = int(stats.TotalRAM / uint64(t.totalDriveCount*(blockSizeLarge+blockSizeSmall)+int(blockSizeV1*2+blockSizeV2*2)))
	} else {
		apiRequestsMaxPerNode = cfg.RequestsMax

	}
	logger.Infof("apiRequestsMaxPerNode: %d", apiRequestsMaxPerNode)
	if cap(t.requestsPool) < apiRequestsMaxPerNode {
		// Only replace if needed.
		// Existing requests will use the previous limit,
		// but new requests will use the new limit.
		// There will be a short overlap window,
		// but this shouldn't last long.
		t.requestsPool = make(chan struct{}, apiRequestsMaxPerNode)
	}
	t.requestsDeadline = cfg.RequestsDeadline
	t.listQuorum = cfg.GetListQuorum()
}

func (t *apiConfig) getListQuorum() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.listQuorum
}

func (t *apiConfig) getCorsAllowOrigins() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	corsAllowOrigins := make([]string, len(t.corsAllowOrigins))
	copy(corsAllowOrigins, t.corsAllowOrigins)
	return corsAllowOrigins
}

func (t *apiConfig) getClusterDeadline() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.clusterDeadline == 0 {
		return 10 * time.Second
	}

	return t.clusterDeadline
}

func (t *apiConfig) getRequestsPool() (chan struct{}, time.Duration) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.requestsPool == nil {
		return nil, time.Duration(0)
	}

	return t.requestsPool, t.requestsDeadline
}

// maxClients throttles the S3 API calls
func maxClients(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool, deadline := globalAPIConfig.getRequestsPool()
		if pool == nil {
			f.ServeHTTP(w, r)
			return
		}

		globalHTTPStats.addRequestsInQueue(1)

		deadlineTimer := time.NewTimer(deadline)
		defer deadlineTimer.Stop()
		max, cur := GetRequestQueue()
		logger.Infof("===> maxClients check! current: %d, max: %d", cur, max)
		select {
		case pool <- struct{}{}:
			logger.Info("serving......")
			defer func() { <-pool }()
			globalHTTPStats.addRequestsInQueue(-1)
			f.ServeHTTP(w, r)
		case <-deadlineTimer.C:
			// Send a http timeout message
			writeErrorResponse(r.Context(), w,
				errorCodes.ToAPIErr(ErrOperationMaxedOut),
				r.URL)
			globalHTTPStats.addRequestsInQueue(-1)
			return
		case <-r.Context().Done():
			globalHTTPStats.addRequestsInQueue(-1)
			return
		}
	}
}

func (t *apiConfig) getReplicationFailedWorkers() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.replicationFailedWorkers
}

func (t *apiConfig) getReplicationWorkers() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.replicationWorkers
}

// GetRequestQueue 获取请求数（最大请求数，当前请求数）
func GetRequestQueue() (max int, current int) {
	max = cap(globalAPIConfig.requestsPool)
	current = int(globalHTTPStats.s3RequestsInQueue)
	return max, current
}
