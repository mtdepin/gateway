

package dsync

import "context"

// LockArgs is minimal required values for any dsync compatible lock operation.
type LockArgs struct {
	// Unique ID of lock/unlock request.
	UID string

	// Resources contains single or multiple entries to be locked/unlocked.
	Resources []string

	// Source contains the line number, function and file name of the code
	// on the client node that requested the lock.
	Source string

	// Owner represents unique ID for this instance, an owner who originally requested
	// the locked resource, useful primarily in figuring our stale locks.
	Owner string

	// Quorum represents the expected quorum for this lock type.
	Quorum int
}

// NetLocker is dsync compatible locker interface.
type NetLocker interface {
	// Do read lock for given LockArgs.  It should return
	// * a boolean to indicate success/failure of the operation
	// * an error on failure of lock request operation.
	RLock(ctx context.Context, args LockArgs) (bool, error)

	// Do write lock for given LockArgs. It should return
	// * a boolean to indicate success/failure of the operation
	// * an error on failure of lock request operation.
	Lock(ctx context.Context, args LockArgs) (bool, error)

	// Do read unlock for given LockArgs. It should return
	// * a boolean to indicate success/failure of the operation
	// * an error on failure of unlock request operation.
	// Canceling the context will abort the remote call.
	// In that case, the resource may or may not be unlocked.
	RUnlock(ctx context.Context, args LockArgs) (bool, error)

	// Do write unlock for given LockArgs. It should return
	// * a boolean to indicate success/failure of the operation
	// * an error on failure of unlock request operation.
	// Canceling the context will abort the remote call.
	// In that case, the resource may or may not be unlocked.
	Unlock(ctx context.Context, args LockArgs) (bool, error)

	// Refresh the given lock to prevent it from becoming stale
	Refresh(ctx context.Context, args LockArgs) (bool, error)

	// Unlock (read/write) forcefully for given LockArgs. It should return
	// * a boolean to indicate success/failure of the operation
	// * an error on failure of unlock request operation.
	ForceUnlock(ctx context.Context, args LockArgs) (bool, error)

	// Returns underlying endpoint of this lock client instance.
	String() string

	// Close closes any underlying connection to the service endpoint
	Close() error

	// Is the underlying connection online? (is always true for any local lockers)
	IsOnline() bool

	// Is the underlying locker local to this server?
	IsLocal() bool
}
