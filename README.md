# rbac
a Role and Resource Based Access Control implementation in golang

![ci](https://github.com/jacexh/rbac/workflows/ci/badge.svg)
[![codecov](https://codecov.io/gh/jacexh/rbac/branch/master/graph/badge.svg)](https://codecov.io/gh/jacexh/rbac)



## Installation

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
