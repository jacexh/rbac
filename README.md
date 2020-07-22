# rbac
a Role and Resource Based Access Control implementation in golang

![ci](https://github.com/jacexh/rbac/workflows/ci/badge.svg)
[![codecov](https://codecov.io/gh/jacexh/rbac/branch/master/graph/badge.svg)](https://codecov.io/gh/jacexh/rbac)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/jacexh/rbac)](https://pkg.go.dev/github.com/jacexh/rbac)
[![Go Report Card](https://goreportcard.com/badge/github.com/jacexh/rbac)](https://goreportcard.com/report/github.com/jacexh/rbac)

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
