

package logger

import (
	"github.com/minio/minio/internal/config"
)

// Help template for logger http and audit
var (
	Help = config.HelpKVS{
		config.HelpKV{
			Key:         Endpoint,
			Description: `HTTP(s) endpoint e.g. "http://localhost:8080/minio/logs/server"`,
			Type:        "url",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         AuthToken,
			Description: `opaque string or JWT authorization token`,
			Optional:    true,
			Type:        "string",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         config.Comment,
			Description: config.DefaultComment,
			Optional:    true,
			Type:        "sentence",
		},
	}

	HelpWebhook = config.HelpKVS{
		config.HelpKV{
			Key:         Endpoint,
			Description: `HTTP(s) endpoint e.g. "http://localhost:8080/minio/logs/audit"`,
			Type:        "url",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         AuthToken,
			Description: `opaque string or JWT authorization token`,
			Optional:    true,
			Type:        "string",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         ClientCert,
			Description: "mTLS certificate for Audit Webhook authentication",
			Optional:    true,
			Type:        "string",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         ClientKey,
			Description: "mTLS certificate key for Audit Webhook authentication",
			Optional:    true,
			Type:        "string",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         config.Comment,
			Description: config.DefaultComment,
			Optional:    true,
			Type:        "sentence",
		},
	}

	HelpKafka = config.HelpKVS{
		config.HelpKV{
			Key:         KafkaBrokers,
			Description: "comma separated list of Kafka broker addresses",
			Type:        "csv",
		},
		config.HelpKV{
			Key:         KafkaTopic,
			Description: "Kafka topic used for bucket notifications",
			Optional:    true,
			Type:        "string",
		},
		config.HelpKV{
			Key:         KafkaSASLUsername,
			Description: "username for SASL/PLAIN or SASL/SCRAM authentication",
			Optional:    true,
			Type:        "string",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         KafkaSASLPassword,
			Description: "password for SASL/PLAIN or SASL/SCRAM authentication",
			Optional:    true,
			Type:        "string",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         KafkaSASLMechanism,
			Description: "sasl authentication mechanism, default 'plain'",
			Optional:    true,
			Type:        "string",
		},
		config.HelpKV{
			Key:         KafkaTLSClientAuth,
			Description: "clientAuth determines the Kafka server's policy for TLS client auth",
			Optional:    true,
			Type:        "string",
		},
		config.HelpKV{
			Key:         KafkaSASL,
			Description: "set to 'on' to enable SASL authentication",
			Optional:    true,
			Type:        "on|off",
		},
		config.HelpKV{
			Key:         KafkaTLS,
			Description: "set to 'on' to enable TLS",
			Optional:    true,
			Type:        "on|off",
		},
		config.HelpKV{
			Key:         KafkaTLSSkipVerify,
			Description: `trust server TLS without verification, defaults to "on" (verify)`,
			Optional:    true,
			Type:        "on|off",
		},
		config.HelpKV{
			Key:         KafkaClientTLSCert,
			Description: "path to client certificate for mTLS auth",
			Optional:    true,
			Type:        "path",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         KafkaClientTLSKey,
			Description: "path to client key for mTLS auth",
			Optional:    true,
			Type:        "path",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         KafkaVersion,
			Description: "specify the version of the Kafka cluster",
			Optional:    true,
			Type:        "string",
		},
		config.HelpKV{
			Key:         config.Comment,
			Description: config.DefaultComment,
			Optional:    true,
			Type:        "sentence",
		},
	}
)
