

package ldap

import "github.com/minio/minio/internal/config"

// Help template for LDAP identity feature.
var (
	Help = config.HelpKVS{
		config.HelpKV{
			Key:         ServerAddr,
			Description: `AD/LDAP server address e.g. "myldapserver.com:636"`,
			Type:        "address",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         STSExpiry,
			Description: `[DEPRECATED] temporary credentials validity duration in s,m,h,d. Default is "1h"`,
			Optional:    true,
			Type:        "duration",
		},
		config.HelpKV{
			Key:         LookupBindDN,
			Description: `DN for LDAP read-only service account used to perform DN and group lookups`,
			Optional:    true,
			Type:        "string",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         LookupBindPassword,
			Description: `Password for LDAP read-only service account used to perform DN and group lookups`,
			Optional:    true,
			Type:        "string",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         UserDNSearchBaseDN,
			Description: `Base LDAP DN to search for user DN`,
			Optional:    true,
			Type:        "string",
		},
		config.HelpKV{
			Key:         UserDNSearchFilter,
			Description: `Search filter to lookup user DN`,
			Optional:    true,
			Type:        "string",
		},
		config.HelpKV{
			Key:         UsernameFormat,
			Description: `";" separated list of username bind DNs e.g. "uid=%s,cn=accounts,dc=myldapserver,dc=com"`,
			Optional:    true,
			Type:        "list",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         GroupSearchFilter,
			Description: `search filter for groups e.g. "(&(objectclass=groupOfNames)(memberUid=%s))"`,
			Optional:    true,
			Type:        "string",
		},
		config.HelpKV{
			Key:         GroupSearchBaseDN,
			Description: `";" separated list of group search base DNs e.g. "dc=myldapserver,dc=com"`,
			Optional:    true,
			Type:        "list",
		},
		config.HelpKV{
			Key:         TLSSkipVerify,
			Description: `trust server TLS without verification, defaults to "off" (verify)`,
			Optional:    true,
			Type:        "on|off",
		},
		config.HelpKV{
			Key:         ServerInsecure,
			Description: `allow plain text connection to AD/LDAP server, defaults to "off"`,
			Optional:    true,
			Type:        "on|off",
		},
		config.HelpKV{
			Key:         ServerStartTLS,
			Description: `use StartTLS connection to AD/LDAP server, defaults to "off"`,
			Optional:    true,
			Type:        "on|off",
		},
		config.HelpKV{
			Key:         config.Comment,
			Description: config.DefaultComment,
			Optional:    true,
			Type:        "sentence",
		},
	}
)
