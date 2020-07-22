package rbac

type (
	// SimpleResource a simple resource implement of Resource interface
	SimpleResource struct {
		id ResourceID
	}
)

// NewSimpleResource factory method of SimpleResource
func NewSimpleResource(id ResourceID) Resource {
	return &SimpleResource{
		id: id,
	}
}

// ID return resource id
func (resource *SimpleResource) ID() ResourceID {
	return resource.id
}
