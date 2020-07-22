package rbac

type (
	// Role role interface
	Role interface {
		ID() RoleID
		Grant(Resource, ...Permission) error
		Deny(ResourceID, ...Permission)
		Permissions() map[ResourceID][]Permission
		Permit(ResourceID, Permission) bool
	}

	// Resource resource interface
	Resource interface {
		ID() ResourceID
	}

	// RoleID role identity
	RoleID string

	// ResourceID role identity
	ResourceID string

	// Permission ...
	Permission string
)

const (
	// PermissionAny build-in permission
	PermissionAny Permission = "*"
	// PermissionCreate build-in permission
	PermissionCreate Permission = "create"
	// PermissionUpdate build-in permission
	PermissionUpdate Permission = "update"
	// PermissionGet build-in permission
	PermissionGet Permission = "get"
	// PermissionDelete build-in permission
	PermissionDelete Permission = "delete"
)
