

package config

import "github.com/minio/minio/internal/auth"

//// One time migration code section

// SetCredentials - One time migration code needed, for migrating from older config to new for server credentials.
func SetCredentials(c Config, cred auth.Credentials) {
	creds, err := auth.CreateCredentials(cred.AccessKey, cred.SecretKey)
	if err != nil {
		return
	}
	if !creds.IsValid() {
		return
	}
	c[CredentialsSubSys][Default] = KVS{
		KV{
			Key:   AccessKey,
			Value: cred.AccessKey,
		},
		KV{
			Key:   SecretKey,
			Value: cred.SecretKey,
		},
	}
}

// SetRegion - One time migration code needed, for migrating from older config to new for server Region.
func SetRegion(c Config, name string) {
	if name == "" {
		return
	}
	c[RegionSubSys][Default] = KVS{
		KV{
			Key:   RegionName,
			Value: name,
		},
	}
}
