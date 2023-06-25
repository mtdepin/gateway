

package http

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger/message/audit"
	"github.com/minio/minio/maitian/config"
	"github.com/olivere/elastic/v7"
)

// Timeout for the webhook http call
const webhookCallTimeout = 5 * time.Second

// Config http logger target
type Config struct {
	Enabled    bool              `json:"enabled"`
	Name       string            `json:"name"`
	UserAgent  string            `json:"userAgent"`
	Endpoint   string            `json:"endpoint"`
	AuthToken  string            `json:"authToken"`
	ClientCert string            `json:"clientCert"`
	ClientKey  string            `json:"clientKey"`
	Transport  http.RoundTripper `json:"-"`

	// Custom logger
	LogOnce func(ctx context.Context, err error, id interface{}, errKind ...interface{}) `json:"-"`
}

// Target implements logger.Target and sends the json
// format of a log entry to the configured http endpoint.
// An internal buffer of logs is maintained but when the
// buffer is full, new logs are just ignored and an error
// is returned to the caller.
type Target struct {
	// Channel of log entries
	logCh chan interface{}

	config Config
}

// Endpoint returns the backend endpoint
func (h *Target) Endpoint() string {
	return h.config.Endpoint
}

func (h *Target) String() string {
	return h.config.Name
}

// Init validate and initialize the http target
func (h *Target) Init() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*webhookCallTimeout)
	defer cancel()

	if config.GetString("elasticsearch.endpoint") != "" {
		h.config.Endpoint = config.GetString("elasticsearch.endpoint")
	}
	endpoint := h.config.Endpoint + "/_cat/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}

	// req.Header.Set(xhttp.ContentType, "application/json")

	// Set user-agent to indicate MinIO release
	// version to the configured log endpoint
	// req.Header.Set("User-Agent", h.config.UserAgent)

	username := config.GetString("elasticsearch.username")
	password := config.GetString("elasticsearch.password")
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	if h.config.AuthToken != "" {
		req.Header.Set("Authorization", h.config.AuthToken)
	}

	client := http.Client{Transport: h.config.Transport}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	// Drain any response.
	xhttp.DrainBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusForbidden:
			return fmt.Errorf("%s returned '%s', please check if your auth token is correctly set",
				h.config.Endpoint, resp.Status)
		}
		return fmt.Errorf("%s returned '%s', please check your endpoint configuration",
			h.config.Endpoint, resp.Status)
	}

	go h.startHTTPLogger()
	return nil
}

func (h *Target) startHTTPLogger() {
	// Create a routine which sends json logs received
	// from an internal channel.
	es, err := connectES([]string{config.GetString("elasticsearch.endpoint")}, config.GetString("elasticsearch.username"), config.GetString("elasticsearch.password"))
	if err != nil {
		fmt.Println(err.Error())
	}
	go func(es *elastic.Client) {
		for entry := range h.logCh {
			ctx := context.Background()
			_, err := es.Index().Index("bucket_name_" + entry.(audit.Entry).BucketName).BodyJson(entry).Do(ctx)
			if err != nil {
				h.config.LogOnce(ctx, fmt.Errorf("%s returned '%s'", h.config.Endpoint, err.Error()), h.config.Endpoint)
				return
			}

		}
	}(es)
}

func connectES(address []string, userName, password string) (*elastic.Client, error) {
	client, err := elastic.NewClient(elastic.SetURL(address...),
		elastic.SetBasicAuth(userName, password),
		elastic.SetHealthcheckInterval(10*time.Second),
		elastic.SetErrorLog(log.New(os.Stderr, "ELASTIC ", log.LstdFlags)),
		elastic.SetInfoLog(log.New(os.Stdout, "", log.LstdFlags)),
		elastic.SetSniff(false))
	if err != nil {
		return nil, err
	}
	return client, nil
}

// New initializes a new logger target which
// sends log over http to the specified endpoint
func New(config Config) *Target {
	h := &Target{
		logCh:  make(chan interface{}, 10000),
		config: config,
	}

	return h
}

// Send log message 'e' to http target.
func (h *Target) Send(entry interface{}, errKind string) error {
	select {
	case h.logCh <- entry:
	default:
		// log channel is full, do not wait and return
		// an error immediately to the caller
		return errors.New("log buffer full")
	}

	return nil
}
