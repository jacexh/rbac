package rbac

import (
	"errors"
	"sync"
)

type (
	// SimpleRole a simple role implement of Role interface
	SimpleRole struct {
		name        RoleID
		permissions map[ResourceID]map[Permission]struct{}
		resources   map[ResourceID]Resource
		mu          sync.RWMutex
	}
)

// NewSimpleRole factory method of SimpleRole
func NewSimpleRole(id RoleID) Role {
	return &SimpleRole{
		name:        id,
		permissions: map[ResourceID]map[Permission]struct{}{},
		resources:   map[ResourceID]Resource{},
	}
}

// ID return role id
func (role *SimpleRole) ID() RoleID {
	return role.name
}

// Grant grant these permissions to the resource
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

// Deny remove these permissions from the resource
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

// Permissions return all permissions granted to the role
func (role *SimpleRole) Permissions() map[ResourceID][]Permission {
	role.mu.RLock()
	defer role.mu.RUnlock()

	ret := make(map[ResourceID][]Permission)
	for rid, res := range role.permissions {
		ret[rid] = make([]Permission, len(res))
		index := 0
		for perm := range res {
			ret[rid][index] = perm
			index++
		}
	}
	return ret
}

// Permit check if role granted the permission of resource
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
