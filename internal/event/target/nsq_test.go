

package target

import (
	"testing"

	xnet "github.com/minio/pkg/net"
)

func TestNSQArgs_Validate(t *testing.T) {
	type fields struct {
		Enable      bool
		NSQDAddress xnet.Host
		Topic       string
		TLS         struct {
			Enable     bool
			SkipVerify bool
		}
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "test1_missing_topic",
			fields: fields{
				Enable: true,
				NSQDAddress: xnet.Host{
					Name:      "127.0.0.1",
					Port:      4150,
					IsPortSet: true,
				},
				Topic: "",
			},
			wantErr: true,
		},
		{
			name: "test2_disabled",
			fields: fields{
				Enable:      false,
				NSQDAddress: xnet.Host{},
				Topic:       "topic",
			},
			wantErr: false,
		},
		{
			name: "test3_OK",
			fields: fields{
				Enable: true,
				NSQDAddress: xnet.Host{
					Name:      "127.0.0.1",
					Port:      4150,
					IsPortSet: true,
				},
				Topic: "topic",
			},
			wantErr: false,
		},
		{
			name: "test4_emptynsqdaddr",
			fields: fields{
				Enable:      true,
				NSQDAddress: xnet.Host{},
				Topic:       "topic",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NSQArgs{
				Enable:      tt.fields.Enable,
				NSQDAddress: tt.fields.NSQDAddress,
				Topic:       tt.fields.Topic,
			}
			if err := n.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("NSQArgs.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
