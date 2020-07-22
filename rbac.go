package rbac

import (
	"encoding/json"
	"errors"
	"sync"
)

type (
	// RBAC Role&&Role Based Access Control Model
	RBAC struct {
		roles        map[RoleID]Role
		RoleImpl     func(RoleID) Role
		ResourceImpl func(ResourceID) Resource
		mu           sync.RWMutex
	}
)

// NewRBAC RBAC Factory method
func NewRBAC() *RBAC {
	return &RBAC{roles: map[RoleID]Role{}}
}

// RegisterRole add new role to rbac
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

// RemoveRole remove role by id
func (rbac *RBAC) RemoveRole(rid RoleID) {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	delete(rbac.roles, rid)
}

// Permit retrue ture or false that this role got the permission of resource
func (rbac *RBAC) Permit(rid RoleID, resID ResourceID, perm Permission) (bool, error) {
	rbac.mu.RLock()
	role, exists := rbac.roles[rid]
	rbac.mu.RUnlock()

	if !exists {
		return false, errors.New("role not found")
	}
	return role.Permit(resID, perm), nil
}

// MarshalJSON implement of json.Marshaller
func (rbac *RBAC) MarshalJSON() ([]byte, error) {
	ret := make(map[RoleID]map[ResourceID][]Permission)
	rbac.mu.RLock()
	for _, role := range rbac.roles {
		ret[role.ID()] = role.Permissions()
	}
	rbac.mu.RUnlock()
	return json.Marshal(ret)
}

// UnmarshalJSON implement of json.Unmarshaller
func (rbac *RBAC) UnmarshalJSON(data []byte) error {
	ret := make(map[RoleID]map[ResourceID][]Permission)
	if err := json.Unmarshal(data, &ret); err != nil {
		return err
	}

	if rbac.RoleImpl == nil {
		rbac.RoleImpl = NewSimpleRole
	}
	if rbac.ResourceImpl == nil {
		rbac.ResourceImpl = NewSimpleResource
	}

	rbac.mu.Lock()
	rbac.roles = make(map[RoleID]Role)
	rbac.mu.Unlock()

	for rid, permissions := range ret {
		role := rbac.RoleImpl(rid)
		for resID, perms := range permissions {
			res := rbac.ResourceImpl(resID)
			if err := role.Grant(res, perms...); err != nil {
				return err
			}
		}
		if err := rbac.RegisterRole(role); err != nil {
			return err
		}
	}
	return nil
}
