package rbac

import (
	"errors"
	"sync"
)

type (
	SimpleRole struct {
		name        RoleID
		permissions map[ResourceID]map[Permission]struct{}
		resources   map[ResourceID]Resource
		mu          sync.RWMutex
	}
)

func NewSimpleRole(name string) *SimpleRole {
	return &SimpleRole{
		name:        RoleID(name),
		permissions: map[ResourceID]map[Permission]struct{}{},
		resources:   map[ResourceID]Resource{},
	}
}

func (role *SimpleRole) ID() RoleID {
	return role.name
}

func (role *SimpleRole) Grant(res Resource, permissions ...Permission) error {
	if res.ID() == "" {
		return errors.New("bad resource id")
	}

	role.mu.Lock()
	defer role.mu.Unlock()

	_, exists := role.resources[res.ID()]
	if !exists {
		role.resources[res.ID()] = res
		role.permissions[res.ID()] = make(map[Permission]struct{})
	}

	for _, permission := range permissions {
		role.permissions[res.ID()][permission] = struct{}{}
	}
	return nil
}

func (role *SimpleRole) Deny(rid ResourceID, permissions ...Permission) {
	role.mu.Lock()
	defer role.mu.Unlock()

	_, exists := role.resources[rid]
	if !exists {
		return
	}

	for _, perm := range permissions {
		if perm == PermissionAny {
			delete(role.resources, rid)
			delete(role.permissions, rid)
			return
		}
		delete(role.permissions[rid], perm)
	}
	// no permission left, delete this resource
	if len(role.permissions[rid]) == 0 {
		delete(role.resources, rid)
		delete(role.permissions, rid)
	}
	return
}

func (role *SimpleRole) Permissions() map[ResourceID][]Permission {
	role.mu.RLock()
	defer role.mu.RUnlock()

	ret := make(map[ResourceID][]Permission)
	for rid, res := range role.permissions {
		ret[rid] = make([]Permission, len(res))
		index := 0
		for perm, _ := range res {
			ret[rid][index] = perm
			index++
		}
	}
	return ret
}

func (role *SimpleRole) Permit(res ResourceID, per Permission) bool {
	role.mu.RLock()
	defer role.mu.RUnlock()

	if permissions, exists := role.permissions[res]; exists {
		if _, exists := permissions[PermissionAny]; exists {
			return true
		}
		if _, exists := permissions[per]; exists {
			return true
		}
	}
	return false
}
