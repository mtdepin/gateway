package cmd

// GatewayMinioSysTmp prefix is used in Azure/GCS gateway for save metadata sent by Initialize Multipart Upload API.
const (
	S3BackendGateway = "s3"
	MtStorageGateway = "mtstorage"
)

// Gateway represents a gateway backend.
type Gateway interface {
	// Name returns the unique name of the gateway.
	Name() string

	// NewGatewayLayer returns a new  ObjectLayer.
	NewGatewayLayer() (ObjectLayer, error)
}
