package rbac

type (
	SimpleResource struct {
		id ResourceID
	}
)

func NewSimpleResource(id string) *SimpleResource {
	return &SimpleResource{
		id: ResourceID(id),
	}
}

func (resource *SimpleResource) ID() ResourceID {
	return resource.id
}
