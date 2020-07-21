package rbac

import (
	"errors"
	"sync"
)

type (
	RBAC struct {
		roles map[RoleID]Role
		mu    sync.RWMutex
	}
)

func NewRBAC() *RBAC {
	return &RBAC{roles: map[RoleID]Role{}}
}

func (rbac *RBAC) RegisterRole(role Role) error {
	if role.ID() == "" {
		return errors.New("bad role id")
	}
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	if _, exists := rbac.roles[role.ID()]; exists {
		return errors.New("conflicted roles")
	}
	rbac.roles[role.ID()] = role
	return nil
}

func (rbac *RBAC) RemoveRole(rid RoleID) {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	delete(rbac.roles, rid)
}

func (rbac *RBAC) Permit(rid RoleID, resID ResourceID, perm Permission) (bool, error) {
	rbac.mu.RLock()
	role, exists := rbac.roles[rid]
	rbac.mu.RUnlock()

	if !exists {
		return false, errors.New("role not found")
	}
	return role.Permit(resID, perm), nil
}
