package alloc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"idips/internal/model"
	"idips/internal/store"
)

var ErrPoolExhausted = errors.New("fake-IP pool exhausted")
var ErrLeaseNotFound = errors.New("lease not found")

type Allocator struct {
	mu    sync.Mutex
	store *store.Store
	log   *slog.Logger
	ttl   func() time.Duration
	cidr  *net.IPNet
	base  uint32
	size  uint32
	used  map[uint32]string
}

type Stats struct {
	CIDR string
	Size uint32
	Used int
	Free uint32
}

func New(st *store.Store, cidr string, ttl func() time.Duration, log *slog.Logger) (*Allocator, error) {
	a := &Allocator{store: st, log: log, ttl: ttl, used: make(map[uint32]string)}
	if err := a.Reconfigure(cidr); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Allocator) Reconfigure(cidr string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid pool CIDR %q: %w", cidr, err)
	}
	ip4 := network.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("pool CIDR %q is not IPv4", cidr)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("pool CIDR %q is not IPv4", cidr)
	}
	if ones < 8 || ones > 30 {
		return fmt.Errorf("pool CIDR %q must have a prefix between /8 and /30", cidr)
	}
	base := binary.BigEndian.Uint32(ip4)
	size := uint32(1) << uint(32-ones)

	a.mu.Lock()
	defer a.mu.Unlock()

	leases, err := a.store.LoadActiveLeases(time.Now())
	if err != nil {
		return err
	}
	used := make(map[uint32]string, len(leases))
	for _, l := range leases {
		ip := net.ParseIP(l.FakeIP).To4()
		if ip == nil {
			continue
		}
		v := binary.BigEndian.Uint32(ip)
		if v >= base && v < base+size {
			used[v] = l.TargetDomain
		} else {
			_ = a.store.DeleteLease(l.ID)
			a.log.Warn("removed lease outside new pool", "fake_ip", l.FakeIP, "domain", l.TargetDomain)
		}
	}
	a.cidr = network
	a.base = base
	a.size = size
	a.used = used
	a.log.Info("fake-IP pool configured", "cidr", cidr, "size", size, "active", len(used))
	return nil
}

func (a *Allocator) CIDR() *net.IPNet {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cidr
}

func (a *Allocator) Contains(ip net.IP) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	ip4 := ip.To4()
	return ip4 != nil && a.cidr != nil && a.cidr.Contains(ip4)
}

func (a *Allocator) GetOrCreate(domain string, ips []net.IP, clientKey string) (model.Lease, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	ttl := a.ttl()
	targetIPs := ipsToStrings(ips)

	existing, err := a.store.GetLeaseByDomain(domain)
	if err == nil {
		if existing.ExpiresAt.After(now) {
			existing.TargetIPs = targetIPs
			existing.ExpiresAt = now.Add(ttl)
			if clientKey != "" {
				existing.ClientKey = clientKey
			}
			if err := a.store.UpdateLease(existing); err != nil {
				return model.Lease{}, err
			}
			return existing, nil
		}
		if err := a.store.DeleteLease(existing.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return model.Lease{}, err
		}
		if v, ok := ipToUint32(existing.FakeIP); ok {
			delete(a.used, v)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return model.Lease{}, err
	}

	v, err := a.allocateLocked(domain)
	if err != nil {
		return model.Lease{}, err
	}
	lease := model.Lease{
		FakeIP:       uint32ToIP(v).String(),
		TargetDomain: domain,
		TargetIPs:    targetIPs,
		ClientKey:    clientKey,
		ExpiresAt:    now.Add(ttl),
	}
	id, err := a.store.CreateLease(lease)
	if err != nil {
		delete(a.used, v)
		return model.Lease{}, err
	}
	lease.ID = id
	a.used[v] = domain
	a.log.Debug("allocated fake IP", "domain", domain, "fake_ip", lease.FakeIP, "lease_until", lease.ExpiresAt)
	return lease, nil
}

func (a *Allocator) allocateLocked(domain string) (uint32, error) {
	if a.size == 0 {
		return 0, errors.New("allocator not configured")
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(domain))
	start := h.Sum32() % a.size
	for i := uint32(0); i < a.size; i++ {
		idx := (start + i) % a.size
		if idx == 0 || idx == a.size-1 {
			continue
		}
		v := a.base + idx
		if _, inUse := a.used[v]; inUse {
			continue
		}
		return v, nil
	}
	return 0, ErrPoolExhausted
}

func (a *Allocator) GetActiveByDomain(domain string) (model.Lease, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	l, err := a.store.GetLeaseByDomain(domain)
	if errors.Is(err, store.ErrNotFound) {
		return l, ErrLeaseNotFound
	}
	if err != nil {
		return l, err
	}
	if !l.ExpiresAt.After(time.Now()) {
		if err := a.store.DeleteLease(l.ID); err == nil {
			if v, ok := ipToUint32(l.FakeIP); ok {
				delete(a.used, v)
			}
		}
		return l, ErrLeaseNotFound
	}
	return l, nil
}

func (a *Allocator) GetActiveByIP(ipStr string) (model.Lease, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	l, err := a.store.GetLeaseByIP(ipStr)
	if errors.Is(err, store.ErrNotFound) {
		return l, ErrLeaseNotFound
	}
	if err != nil {
		return l, err
	}
	if !l.ExpiresAt.After(time.Now()) {
		if err := a.store.DeleteLease(l.ID); err == nil {
			if v, ok := ipToUint32(l.FakeIP); ok {
				delete(a.used, v)
			}
		}
		return l, ErrLeaseNotFound
	}
	return l, nil
}

func (a *Allocator) TouchDomain(domain string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	l, err := a.store.GetLeaseByDomain(domain)
	if err != nil || !l.ExpiresAt.After(time.Now()) {
		return
	}
	_ = a.store.TouchLease(l.ID, time.Now().Add(a.ttl()))
}

func (a *Allocator) TouchIP(ipStr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	l, err := a.store.GetLeaseByIP(ipStr)
	if err != nil || !l.ExpiresAt.After(time.Now()) {
		return
	}
	_ = a.store.TouchLease(l.ID, time.Now().Add(a.ttl()))
}

func (a *Allocator) Delete(id int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	l, err := a.store.GetLeaseByID(id)
	if errors.Is(err, store.ErrNotFound) {
		return ErrLeaseNotFound
	}
	if err != nil {
		return err
	}
	if err := a.store.DeleteLease(id); err != nil {
		return err
	}
	if v, ok := ipToUint32(l.FakeIP); ok {
		delete(a.used, v)
	}
	return nil
}

func (a *Allocator) GC() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if _, err := a.store.DeleteExpiredLeases(now); err != nil {
		return err
	}
	leases, err := a.store.LoadActiveLeases(now)
	if err != nil {
		return err
	}
	used := make(map[uint32]string, len(leases))
	for _, l := range leases {
		if v, ok := ipToUint32(l.FakeIP); ok && a.cidr != nil && a.cidr.Contains(uint32ToIP(v)) {
			used[v] = l.TargetDomain
		}
	}
	a.used = used
	return nil
}

func (a *Allocator) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	cidr := ""
	if a.cidr != nil {
		cidr = a.cidr.String()
	}
	used := uint32(len(a.used))
	free := uint32(0)
	if a.size > used {
		free = a.size - used
	}
	return Stats{CIDR: cidr, Size: a.size, Used: len(a.used), Free: free}
}

func (a *Allocator) ActiveLeases() ([]model.Lease, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.store.LoadActiveLeases(time.Now())
}

func (a *Allocator) DomainForIP(ipStr string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := ipToUint32(ipStr)
	if !ok {
		return "", false
	}
	d, ok := a.used[v]
	return d, ok
}

func (a *Allocator) SortedUsed() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.used))
	for v := range a.used {
		out = append(out, uint32ToIP(v).String())
	}
	sort.Strings(out)
	return out
}

func ipsToStrings(ips []net.IP) []string {
	seen := make(map[string]struct{}, len(ips))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		s := ip.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func ipToUint32(s string) (uint32, bool) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip), true
}

func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}
