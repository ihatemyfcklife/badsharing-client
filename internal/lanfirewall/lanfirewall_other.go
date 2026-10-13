//go:build !linux

package lanfirewall

import "context"

type Session struct{}

func (s *Session) Close() error { return nil }
func Prepare(_ context.Context, _ int, _, _ uint16, _ []string) (*Session, string, error) {
	return nil, "No Linux firewall setup needed", nil
}
func RunHelper(_ []string) (bool, error) { return false, nil }
