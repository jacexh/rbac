package rbac

type (
	Role interface {
		ID() RoleID
		Grant(Resource, ...Permission) error
		Deny(ResourceID, ...Permission)
		Permissions() map[ResourceID][]Permission
		Permit(ResourceID, Permission) bool
	}

	Resource interface {
		ID() ResourceID
	}

	RoleID string

	ResourceID string

	Permission string
)

const (
	PermissionAny    Permission = "*"
	PermissionCreate Permission = "create"
	PermissionUpdate Permission = "update"
	PermissionGet    Permission = "get"
	PermissionDelete Permission = "delete"
)
