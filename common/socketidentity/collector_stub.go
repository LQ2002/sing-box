//go:build !linux

package socketidentity

func Open(Config) (*Collector, error) { return nil, ErrUnsupported }
func Remove(string) error             { return ErrUnsupported }
