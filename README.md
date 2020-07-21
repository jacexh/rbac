# rbac
a Role and Resource Based Access Control implementation in golang

![ci](https://github.com/jacexh/rbac/workflows/ci/badge.svg)


## Install

```
go get github.com/jacexh/rbac
```

## Example

```go
rbac := NewRBAC()
qa := NewSimpleRole("qa")
deployment := NewSimpleResource("deployment")
qa.Grant(deployment, PermissionGet, PermissionUpdate)
rbac.RegisterRole(qa)
rbac.Permit(qa, deployment.ID(), PermissionGet)
```
