package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	"idips/internal/model"
	"idips/internal/secret"
)

func TestMigrateAddsMatchLogicColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		priority INTEGER NOT NULL DEFAULT 100,
		enabled INTEGER NOT NULL DEFAULT 1,
		match_domain TEXT NOT NULL DEFAULT '',
		domain_mode TEXT NOT NULL DEFAULT 'suffix',
		match_cidr TEXT NOT NULL DEFAULT '',
		match_geoip TEXT NOT NULL DEFAULT '',
		match_asn TEXT NOT NULL DEFAULT '',
		match_client_cidr TEXT NOT NULL DEFAULT '',
		match_port TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL DEFAULT 'proxy',
		upstream_id INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	INSERT INTO rules(name, priority, enabled, match_domain, domain_mode, action, created_at, updated_at)
	VALUES('legacy', 10, 1, 'example.com', 'suffix', 'block', 1, 1);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	rules, err := st.ListRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].MatchLogic != model.LogicAnd {
		t.Fatalf("legacy rules = %+v, want one rule with logic and", rules)
	}
}

func TestCreateRuleNormalizesLogic(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(filepath.Join(t.TempDir(), "test.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	id, err := st.CreateRule(model.Rule{
		Name: "or rule", Priority: 10, Enabled: true, MatchDomain: "example.com",
		DomainMode: "suffix", MatchLogic: model.LogicOr, Action: model.ActionBlock,
	})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := st.GetRule(id)
	if err != nil {
		t.Fatal(err)
	}
	if rule.MatchLogic != model.LogicOr {
		t.Fatalf("logic = %q, want %q", rule.MatchLogic, model.LogicOr)
	}
}
