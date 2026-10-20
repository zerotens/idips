package iptoasn

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Record struct {
	ASN     uint32
	Country string
	Org     string
}

type DB struct {
	v4   []range4
	v6   []range6
	orgs map[uint32]string
}

type range4 struct {
	start   uint32
	end     uint32
	asn     uint32
	country [2]byte
}

type range6 struct {
	start   [16]byte
	end     [16]byte
	asn     uint32
	country [2]byte
}

func Open(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 64*1024)
	header, _ := br.Peek(2)
	var r io.Reader = br
	if len(header) == 2 && header[0] == 0x1f && header[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("open gzip: %w", err)
		}
		defer gz.Close()
		r = gz
	}

	db, err := parse(r)
	if err != nil {
		return nil, err
	}
	sort.Slice(db.v4, func(i, j int) bool { return db.v4[i].start < db.v4[j].start })
	sort.Slice(db.v6, func(i, j int) bool {
		return bytes.Compare(db.v6[i].start[:], db.v6[j].start[:]) < 0
	})
	return db, nil
}

func parse(r io.Reader) (*DB, error) {
	db := &DB{orgs: make(map[uint32]string)}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "\t", 5)
		if len(fields) < 4 {
			continue
		}
		start, err := netip.ParseAddr(strings.TrimSpace(fields[0]))
		if err != nil {
			continue
		}
		end, err := netip.ParseAddr(strings.TrimSpace(fields[1]))
		if err != nil {
			continue
		}
		start = start.Unmap()
		end = end.Unmap()

		asn, err := strconv.ParseUint(strings.TrimSpace(fields[2]), 10, 32)
		if err != nil {
			continue
		}
		var country [2]byte
		if cc := strings.ToUpper(strings.TrimSpace(fields[3])); len(cc) == 2 {
			copy(country[:], cc)
		}
		if org := strings.TrimSpace(fields[4]); org != "" && asn != 0 {
			if _, ok := db.orgs[uint32(asn)]; !ok {
				db.orgs[uint32(asn)] = org
			}
		}

		if start.Is4() && end.Is4() {
			db.v4 = append(db.v4, range4{
				start:   ipv4ToUint32(start.As4()),
				end:     ipv4ToUint32(end.As4()),
				asn:     uint32(asn),
				country: country,
			})
			continue
		}
		if start.Is6() && end.Is6() {
			db.v6 = append(db.v6, range6{
				start:   start.As16(),
				end:     end.As16(),
				asn:     uint32(asn),
				country: country,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read database: %w", err)
	}
	if len(db.v4) == 0 && len(db.v6) == 0 {
		return nil, fmt.Errorf("database contains no ranges")
	}
	return db, nil
}

func (db *DB) Len() int {
	if db == nil {
		return 0
	}
	return len(db.v4) + len(db.v6)
}

func (db *DB) Lookup(ip net.IP) (Record, bool) {
	if db == nil || ip == nil {
		return Record{}, false
	}
	if v4 := ip.To4(); v4 != nil {
		query := binary.BigEndian.Uint32(v4)
		i := sort.Search(len(db.v4), func(i int) bool { return db.v4[i].start > query }) - 1
		if i >= 0 && query <= db.v4[i].end {
			asn := db.v4[i].asn
			return Record{ASN: asn, Country: countryString(db.v4[i].country), Org: db.orgs[asn]}, true
		}
		return Record{}, false
	}
	v16 := ip.To16()
	if v16 == nil {
		return Record{}, false
	}
	var query [16]byte
	copy(query[:], v16)
	i := sort.Search(len(db.v6), func(i int) bool {
		return bytes.Compare(db.v6[i].start[:], query[:]) > 0
	}) - 1
	if i >= 0 && bytes.Compare(query[:], db.v6[i].end[:]) <= 0 {
		asn := db.v6[i].asn
		return Record{ASN: asn, Country: countryString(db.v6[i].country), Org: db.orgs[asn]}, true
	}
	return Record{}, false
}

func ipv4ToUint32(b [4]byte) uint32 {
	return binary.BigEndian.Uint32(b[:])
}

func countryString(cc [2]byte) string {
	if cc[0] == 0 {
		return ""
	}
	if cc[1] == 0 {
		return string(cc[:1])
	}
	return string(cc[:])
}
