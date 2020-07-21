package rbac

type (
	SimpleResource struct {
		id ResourceID
	}
)

func NewSimpleResource(id ResourceID) Resource {
	return &SimpleResource{
		id: id,
	}
}

func (resource *SimpleResource) ID() ResourceID {
	return resource.id
}
