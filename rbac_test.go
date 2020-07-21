package rbac

import (
	"encoding/json"
	"log"
	"sync/atomic"
	"testing"
)

func TestRegisterRole(t *testing.T) {
	rbac := NewRBAC()
	qa := NewSimpleRole("qa")
	err := qa.Grant(NewSimpleResource("github"), PermissionGet)
	if err != nil {
		log.Fatal(err)
	}
	//dev := NewSimpleRole("dev")

	err = rbac.RegisterRole(qa)
	if err != nil {
		log.Fatal(err)
	}

	if ok, _ := rbac.Permit(qa.ID(), ResourceID("github"), PermissionGet); !ok {
		t.FailNow()
	}
}

func TestRemoveRole(t *testing.T) {
	rbac := NewRBAC()
	qa := NewSimpleRole("qa")
	err := qa.Grant(NewSimpleResource("github"), PermissionGet)
	if err != nil {
		log.Fatal(err)
	}
	//dev := NewSimpleRole("dev")

	err = rbac.RegisterRole(qa)
	if err != nil {
		log.Fatal(err)
	}

	if ok, _ := rbac.Permit(qa.ID(), "github", PermissionGet); !ok {
		t.FailNow()
	}

	rbac.RemoveRole(qa.ID())
	if _, err := rbac.Permit(qa.ID(), "github", PermissionGet); err == nil {
		t.FailNow()
	}
}

func TestRBACMarshalJSON(t *testing.T) {
	rbac := NewRBAC()
	qa := NewSimpleRole("qa")
	err := qa.Grant(NewSimpleResource("github"), PermissionGet)
	if err != nil {
		log.Fatal(err)
	}
	//dev := NewSimpleRole("dev")

	err = rbac.RegisterRole(qa)
	if err != nil {
		log.Fatal(err)
	}

	data, err := json.Marshal(rbac)
	if err != nil {
		t.FailNow()
	}
	log.Println(string(data))
}

func TestRBAC_UnmarshalJSON(t *testing.T) {
	rbac := new(RBAC)
	data := []byte(`{"qa":{"github":["get"]}, "dev":{"github": ["create", "get"]}}`)

	err := json.Unmarshal(data, rbac)
	if err != nil {
		log.Fatal(err)
	}

	if ok, _ := rbac.Permit("qa", "github", PermissionGet); !ok {
		t.FailNow()
	}

	if ok, _ := rbac.Permit("dev", "github", PermissionCreate); !ok {
		t.FailNow()
	}
}

func BenchmarkRBAC_Permit(b *testing.B) {
	rbac := NewRBAC()
	qa := NewSimpleRole("qa")
	dev := NewSimpleRole("dev")
	github := NewSimpleResource("github")
	err := qa.Grant(github, PermissionGet)
	if err != nil {
		log.Fatal(err)
	}
	err = dev.Grant(github, PermissionGet, PermissionCreate, PermissionDelete, PermissionUpdate)
	if err != nil {
		log.Fatal(err)
	}

	err = rbac.RegisterRole(qa)
	if err != nil {
		log.Fatal(err)
	}
	err = rbac.RegisterRole(dev)
	if err != nil {
		log.Fatal(err)
	}

	var counts uint32

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			val := atomic.AddUint32(&counts, 1)
			switch {
			case val%2 == 0:
				rbac.Permit(qa.ID(), github.ID(), PermissionCreate)
			case val%2 == 1:
				rbac.Permit(dev.ID(), github.ID(), PermissionCreate)
			}

		}
	})
}
