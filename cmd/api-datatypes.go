package cmd

import (
	"encoding/xml"
	"time"
)

// DeletedObject objects deleted
type DeletedObject struct {
	DeleteMarker          bool   `xml:"DeleteMarker,omitempty"`
	DeleteMarkerVersionID string `xml:"DeleteMarkerVersionId,omitempty"`
	ObjectName            string `xml:"Key,omitempty"`
	VersionID             string `xml:"VersionId,omitempty"`
	Size                  int64  `-`

	// MinIO extensions to support delete marker replication
	// Replication status of DeleteMarker
	DeleteMarkerReplicationStatus string `xml:"DeleteMarkerReplicationStatus,omitempty"`
	// MTime of DeleteMarker on source that needs to be propagated to replica
	DeleteMarkerMTime DeleteMarkerMTime `xml:"DeleteMarkerMTime,omitempty"`
}

// DeleteMarkerMTime is an embedded type containing time.Time for XML marshal
type DeleteMarkerMTime struct {
	time.Time
}

// MarshalXML encodes expiration date if it is non-zero and encodes
// empty string otherwise
func (t DeleteMarkerMTime) MarshalXML(e *xml.Encoder, startElement xml.StartElement) error {
	if t.Time.IsZero() {
		return nil
	}
	return e.EncodeElement(t.Time.Format(time.RFC3339), startElement)
}

// ObjectToDelete carries key name for the object to delete.
type ObjectToDelete struct {
	ObjectName string `xml:"Key"`
	VersionID  string `xml:"VersionId"`
	// Replication status of DeleteMarker
	DeleteMarkerReplicationStatus string `xml:"DeleteMarkerReplicationStatus"`
	// Version ID of delete marker
	DeleteMarkerVersionID string `xml:"DeleteMarkerVersionId"`
}

// createBucketConfiguration container for bucket configuration request from client.
// Used for parsing the location from the request body for Makebucket.
type createBucketLocationConfiguration struct {
	XMLName  xml.Name `xml:"CreateBucketConfiguration" json:"-"`
	Location string   `xml:"LocationConstraint"`
}

// createBucketConfiguration container for bucket configuration request from client.
// Used for parsing the location and storageclass from the request body for Makebucket.
type createBucketConfiguration struct {
	XMLName      xml.Name `xml:"CreateBucketConfiguration" json:"-"`
	Location     string   `xml:"LocationConstraint"`
	StorageClass string   `xml:"StorageClass"`
}

// DeleteObjectsRequest - xml carrying the object key names which needs to be deleted.
type DeleteObjectsRequest struct {
	// Element to enable quiet mode for the request
	Quiet bool
	// List of objects to be deleted
	Objects []ObjectToDelete `xml:"Object"`
}
