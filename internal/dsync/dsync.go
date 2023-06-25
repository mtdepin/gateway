

package dsync

// Dsync represents dsync client object which is initialized with
// authenticated clients, used to initiate lock REST calls.
type Dsync struct {
	// List of rest client objects, one per lock server.
	GetLockers func() ([]NetLocker, string)
}
