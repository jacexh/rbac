package rbac

import (
	"log"
	"reflect"
	"testing"
)

func TestNewSimpleRole(t *testing.T) {
	var role Role
	role = NewSimpleRole("guest")
	if role.ID() != "guest" {
		t.FailNow()
	}
}

func TestRoleGrant(t *testing.T) {
	role := NewSimpleRole("developer")
	github := NewSimpleResource("github")
	err := role.Grant(github, PermissionCreate, PermissionGet)
	if err != nil {
		t.FailNow()
	}

	if !role.Permit(github.ID(), PermissionCreate) {
		t.FailNow()
	}

	if role.Permit(github.ID(), PermissionDelete) {
		t.FailNow()
	}

	err = role.Grant(github, PermissionAny)
	if err != nil {
		t.FailNow()
	}
	if !role.Permit(github.ID(), PermissionDelete) {
		t.FailNow()
	}

	gitlab := NewSimpleResource("gitlab")
	if role.Permit(gitlab.ID(), PermissionAny) {
		t.FailNow()
	}
}

func TestRoleDeny(t *testing.T) {
	var role Role
	role = NewSimpleRole("developer")
	github := NewSimpleResource("github")
	err := role.Grant(github, PermissionCreate, PermissionGet)
	if err != nil {
		t.FailNow()
	}

	if !role.Permit(github.ID(), PermissionCreate) {
		t.FailNow()
	}

	if !role.Permit(github.ID(), PermissionGet) {
		t.FailNow()
	}

	role.Deny(github.ID(), PermissionGet)
	if role.Permit(github.ID(), PermissionGet) {
		t.FailNow()
	}

	role.Deny(github.ID(), PermissionAny)
	if role.Permit(github.ID(), PermissionCreate) {
		t.FailNow()
	}
}

func TestRolePermissions(t *testing.T) {
	var role Role
	role = NewSimpleRole("developer")
	github := NewSimpleResource("github")
	err := role.Grant(github, PermissionCreate, PermissionGet)
	if err != nil {
		t.FailNow()
	}
	gitlab := NewSimpleResource("gitlab")
	err = role.Grant(gitlab, PermissionAny)
	if err != nil {
		t.FailNow()
	}

	ret := map[ResourceID][]Permission{
		"github": {"create", "get"},
		"gitlab": {"*"},
	}

	if !reflect.DeepEqual(ret, role.Permissions()) {
		log.Print(role.Permissions())
		t.FailNow()
	}
}
