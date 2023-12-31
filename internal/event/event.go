

package event

const (
	// NamespaceFormat - namespace log format used in some event targets.
	NamespaceFormat = "namespace"

	// AccessFormat - access log format used in some event targets.
	AccessFormat = "access"

	// AMZTimeFormat - event time format.
	AMZTimeFormat = "2006-01-02T15:04:05.000Z"
)

// Identity represents access key who caused the event.
type Identity struct {
	PrincipalID string `json:"principalId"`
}

// Bucket represents bucket metadata of the event.
type Bucket struct {
	Name          string   `json:"name"`
	OwnerIdentity Identity `json:"ownerIdentity"`
	ARN           string   `json:"arn"`
}

// Object represents object metadata of the event.
type Object struct {
	Key          string            `json:"key"`
	Size         int64             `json:"size,omitempty"`
	ETag         string            `json:"eTag,omitempty"`
	ContentType  string            `json:"contentType,omitempty"`
	UserMetadata map[string]string `json:"userMetadata,omitempty"`
	VersionID    string            `json:"versionId,omitempty"`
	Sequencer    string            `json:"sequencer"`
}

// Metadata represents event metadata.
type Metadata struct {
	SchemaVersion   string `json:"s3SchemaVersion"`
	ConfigurationID string `json:"configurationId"`
	Bucket          Bucket `json:"bucket"`
	Object          Object `json:"object"`
}

// Source represents client information who triggered the event.
type Source struct {
	Host      string `json:"host"`
	Port      string `json:"port"`
	UserAgent string `json:"userAgent"`
}

// Event represents event notification information defined in
// http://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html.
type Event struct {
	EventVersion      string            `json:"eventVersion"`
	EventSource       string            `json:"eventSource"`
	AwsRegion         string            `json:"awsRegion"`
	EventTime         string            `json:"eventTime"`
	EventName         Name              `json:"eventName"`
	UserIdentity      Identity          `json:"userIdentity"`
	RequestParameters map[string]string `json:"requestParameters"`
	ResponseElements  map[string]string `json:"responseElements"`
	S3                Metadata          `json:"s3"`
	Source            Source            `json:"source"`
}

// Log represents event information for some event targets.
type Log struct {
	EventName Name
	Key       string
	Records   []Event
}
