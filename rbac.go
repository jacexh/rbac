package rbac

import (
	"encoding/json"
	"errors"
	"sync"
)

type (
	RBAC struct {
		roles        map[RoleID]Role
		RoleImpl     func(RoleID) Role
		ResourceImpl func(ResourceID) Resource
		mu           sync.RWMutex
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

func (rbac *RBAC) MarshalJSON() ([]byte, error) {
	ret := make(map[RoleID]map[ResourceID][]Permission)
	rbac.mu.RLock()
	for _, role := range rbac.roles {
		ret[role.ID()] = role.Permissions()
	}
	rbac.mu.RUnlock()
	return json.Marshal(ret)
}

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
