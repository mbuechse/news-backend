// copyright Matthias Büchse, 2019
package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
)

type ModuleTxn interface {
	Close()
	Insert(obj object) error
	Update(extant objectMap, obj object) error
	Delete(id string) error
}

type Module interface {
	Init(db *sql.DB) error
	Begin(tx *sql.Tx) ModuleTxn
}

type CompositeModule []Module
type MainModule struct{}
type ModuleDate struct{}
type ModuleTags struct{}
type ModuleEmail struct{}
type ModuleFriendlyId struct{}
type ModuleOwner struct{}
type ModuleJobs struct{}

// from here onwards: implementation

type compositeModuleTxn []ModuleTxn

func (ms compositeModuleTxn) Close() {
	for _, m := range ms {
		m.Close()
	}
}

func (ms compositeModuleTxn) Insert(obj object) error {
	for _, m := range ms {
		if err := m.Insert(obj); err != nil {
			return err
		}
	}
	return nil
}

func (ms compositeModuleTxn) Update(extant objectMap, obj object) error {
	for _, m := range ms {
		if err := m.Update(extant, obj); err != nil {
			return err
		}
	}
	return nil
}

func (ms compositeModuleTxn) Delete(id string) error {
	for i := len(ms) - 1; i >= 0; i-- {
		m := ms[i]
		if err := m.Delete(id); err != nil {
			return err
		}
	}
	return nil
}

func (ms CompositeModule) Init(db *sql.DB) error {
	for _, m := range ms {
		if err := m.Init(db); err != nil {
			return err
		}
	}
	return nil
}

func (ms CompositeModule) Begin(tx *sql.Tx) ModuleTxn {
	var txn = make(compositeModuleTxn, len(ms))
	for i, m := range ms {
		txn[i] = m.Begin(tx)
	}
	return txn
}

const INSERT = 0
const DELETE = 1
const UPDATE = 2

type stmtTxn struct {
	stmt []*sql.Stmt
}
type mainModuleTxn struct{ stmtTxn }
type moduleDateTxn struct{ stmtTxn }
type moduleTagsTxn struct{ stmtTxn }
type moduleEmailTxn struct{ stmtTxn }
type moduleFriendlyIdTxn struct{ stmtTxn }
type moduleOwnerTxn struct{ stmtTxn }
type moduleJobsTxn struct{ stmtTxn }

func NewStmtTxn(tx *sql.Tx, sqlStmt ...string) stmtTxn {
	stmts := make([]*sql.Stmt, len(sqlStmt))
	for i, sqlStmt1 := range sqlStmt {
		stmt, err := tx.Prepare(sqlStmt1)
		if err != nil {
			log.Fatal(err)
		}
		stmts[i] = stmt
	}
	return stmtTxn{stmts}
}

func (txn stmtTxn) Delete(id string) error {
	if _, err := txn.stmt[DELETE].Exec(id); err != nil {
		return err
	}
	return nil
}

func (txn stmtTxn) Close() {
	for _, stmt := range txn.stmt {
		stmt.Close()
	}
}

func (txn mainModuleTxn) upsert(obj object, stmt_idx int) error {
	if attach, ok := obj[":attach:"].(string); ok {
		reattach := func() { obj[":attach:"] = attach }
		defer reattach()
		obj[":attach:"] = nil
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	id := obj["id"].(string)
	typ := obj["type"]
	version := obj["version"]
	if _, ok := typ.(string); !ok {
		typ = nil
	}
	if _, ok := version.(string); !ok {
		version = nil
	}
	if _, err := txn.stmt[stmt_idx].Exec(typ, version, data, id); err != nil {
		return err
	}
	return nil
}

func (txn mainModuleTxn) Insert(obj object) error {
	return txn.upsert(obj, INSERT)
}

func (txn mainModuleTxn) Update(extant objectMap, obj object) error {
	return txn.upsert(obj, UPDATE)
}

func (txn moduleDateTxn) Insert(obj object) error {
	if date, present := obj["date"]; present {
		id := obj["id"].(string)
		if _, err := txn.stmt[INSERT].Exec(id, date); err != nil {
			return err
		}
	}
	return nil
}

func (txn moduleDateTxn) Update(extant objectMap, obj object) error {
	if err := txn.Delete(obj["id"].(string)); err != nil {
		return err
	}
	return txn.Insert(obj)
}

func (txn moduleTagsTxn) Insert(obj object) error {
	if tags, ok := obj["$tags"].([]interface{}); ok {
		id := obj["id"].(string)
		for _, tagi := range tags {
			tagid := tagi.(string)
			if _, err := txn.stmt[INSERT].Exec(id, tagid); err != nil {
				return err
			}
		}
	}
	return nil
}

func (txn moduleTagsTxn) Update(extant objectMap, obj object) error {
	if err := txn.Delete(obj["id"].(string)); err != nil {
		return err
	}
	return txn.Insert(obj)
}

func (txn moduleEmailTxn) Insert(obj object) error {
	if obj["type"] != "account" {
		return nil
	}
	if email, present := obj["email"]; present {
		id := obj["id"].(string)
		if _, err := txn.stmt[INSERT].Exec(id, email); err != nil {
			return err
		}
	}
	return nil
}

func (txn moduleEmailTxn) Update(extant objectMap, obj object) error {
	if err := txn.Delete(obj["id"].(string)); err != nil {
		return err
	}
	return txn.Insert(obj)
}

func (txn moduleFriendlyIdTxn) Insert(obj object) error {
	if friendly, present := obj["friendlyId"]; present {
		id := obj["id"].(string)
		if _, err := txn.stmt[INSERT].Exec(id, friendly); err != nil {
			return err
		}
	}
	return nil
}

func (txn moduleFriendlyIdTxn) Update(extant objectMap, obj object) error {
	if err := txn.Delete(obj["id"].(string)); err != nil {
		return err
	}
	return txn.Insert(obj)
}

func (txn moduleOwnerTxn) Insert(obj object) error {
	if owner, ok := obj["$owner"].(string); ok {
		id := obj["id"].(string)
		if _, err := txn.stmt[INSERT].Exec(id, owner); err != nil {
			return err
		}
	}
	return nil
}

func (txn moduleOwnerTxn) Update(extant objectMap, obj object) error {
	if err := txn.Delete(obj["id"].(string)); err != nil {
		return err
	}
	return txn.Insert(obj)
}

func (txn moduleJobsTxn) Insert(obj object) error {
	if obj[K_TYPE] != "job" || obj[K_STATE] != "running" && obj[K_STATE] != "pending" {
		return nil
	}
	target, ok := obj["$target"].(string)
	if !ok {
		return nil
	}
	id := obj["id"].(string)
	_, err := txn.stmt[INSERT].Exec(id, target)
	return err
}

func (txn moduleJobsTxn) Update(extant objectMap, obj object) error {
	if err := txn.Delete(obj["id"].(string)); err != nil {
		return err
	}
	return txn.Insert(obj)
}

func (MainModule) Begin(tx *sql.Tx) ModuleTxn {
	return mainModuleTxn{NewStmtTxn(tx,
		"insert into objects(type, version, data, id) values(?, ?, ?, ?)",
		"delete from objects where id = ?",
		"update objects set (type, version, data) = (?, ?, ?) where id = ?",
	)}
}

func (ModuleDate) Begin(tx *sql.Tx) ModuleTxn {
	return moduleDateTxn{NewStmtTxn(tx,
		"insert into pr_date(id, date) values(?, ?)",
		"delete from pr_date where id = ?",
	)}
}

func (ModuleTags) Begin(tx *sql.Tx) ModuleTxn {
	return moduleTagsTxn{NewStmtTxn(tx,
		"insert into pr_tags(id, tagid) values(?, ?)",
		"delete from pr_tags where id = ?",
	)}
}

func (ModuleEmail) Begin(tx *sql.Tx) ModuleTxn {
	return moduleEmailTxn{NewStmtTxn(tx,
		"insert into pr_email(id, email) values(?, ?)",
		"delete from pr_email where id = ?",
	)}
}

func (ModuleFriendlyId) Begin(tx *sql.Tx) ModuleTxn {
	return moduleFriendlyIdTxn{NewStmtTxn(tx,
		"insert into pr_friendly(id, friendly) values(?, ?)",
		"delete from pr_friendly where id = ?",
	)}
}

func (ModuleOwner) Begin(tx *sql.Tx) ModuleTxn {
	return moduleOwnerTxn{NewStmtTxn(tx,
		"insert into pr_owner(id, owner) values(?, ?)",
		"delete from pr_owner where id = ?",
	)}
}

func (ModuleJobs) Begin(tx *sql.Tx) ModuleTxn {
	return moduleJobsTxn{NewStmtTxn(tx,
		"insert into pr_job(id, target) values(?, ?)",
		"delete from pr_job where id = ?",
	)}
}

func queryMeta(db *sql.DB, key string, value *string) error {
	rows, err := db.Query("select value from meta where key = ?", key)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(value); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (MainModule) Init(db *sql.DB) error {
	stmt := `PRAGMA foreign_keys=ON; create table if not exists meta (key varchar primary key, value varchar);`
	if _, err := db.Exec(stmt); err != nil {
		return err
	}
	var schemaVersion string = "empty"
	if err := queryMeta(db, "main_module_version", &schemaVersion); err != nil {
		return err
	}
	switch schemaVersion {
	case "empty":
		stmt = `
		drop index if exists idx_type;
		drop table if exists objects;
		create table objects (id uuid not null primary key, type varchar, version varchar, fmt byte default 0, data varchar not null);
		create index idx_type on objects (type);
		insert into meta (key, value) values ("main_module_version", "initial");
		`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	case "initial":
	default:
		return errors.New(fmt.Sprintf("Main schema version unknown: %v", schemaVersion))
	}
	return nil
}

func (ModuleDate) Init(db *sql.DB) error {
	var schemaVersion string = "empty"
	if err := queryMeta(db, "module_date_version", &schemaVersion); err != nil {
		return err
	}
	switch schemaVersion {
	case "empty":
		stmt := `
		drop index if exists idx_date;
		drop table if exists pr_date;
		create table pr_date (id uuid primary key references objects (id) on delete cascade on update cascade, date date);
		create index idx_date on pr_date (date);
		`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
		// TODO compute projection for existing objects!
		stmt = `insert into meta (key, value) values ("module_date_version", "initial");`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	case "initial":
	default:
		return errors.New(fmt.Sprintf("Date schema version unknown: %v", schemaVersion))
	}
	return nil
}

func (ModuleTags) Init(db *sql.DB) error {
	var schemaVersion string = "empty"
	if err := queryMeta(db, "module_tags_version", &schemaVersion); err != nil {
		return err
	}
	switch schemaVersion {
	case "empty":
		stmt := `
		drop index if exists idx_tags;
		drop table if exists pr_tags;
		create table pr_tags (id uuid references objects (id) on delete cascade on update cascade, tagid references objects (id) on update cascade, primary key (id, tagid));
		create index idx_tags on pr_tags (tagid);
		`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
		// TODO compute projection for existing objects!
		stmt = `insert into meta (key, value) values ("module_tags_version", "initial");`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	case "initial":
	default:
		return errors.New(fmt.Sprintf("Tags schema version unknown: %v", schemaVersion))
	}
	return nil
}

func (ModuleEmail) Init(db *sql.DB) error {
	var schemaVersion string = "empty"
	if err := queryMeta(db, "module_email_version", &schemaVersion); err != nil {
		return err
	}
	switch schemaVersion {
	case "empty":
		stmt := `
		drop index if exists idx_email;
		drop table if exists pr_email;
		create table pr_email (id uuid primary key references objects(id) on delete cascade on update cascade, email varchar not null unique);
		create index idx_email on pr_email (email);
		`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
		// TODO compute projection for existing objects!
		stmt = `insert into meta (key, value) values ("module_email_version", "initial");`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	case "initial":
	default:
		return errors.New(fmt.Sprintf("Email schema version unknown: %v", schemaVersion))
	}
	return nil
}

func (ModuleFriendlyId) Init(db *sql.DB) error {
	var schemaVersion string = "empty"
	if err := queryMeta(db, "module_friendlyid_version", &schemaVersion); err != nil {
		return err
	}
	switch schemaVersion {
	case "empty":
		stmt := `
		drop index if exists idx_friendly;
		drop table if exists pr_friendly;
		create table pr_friendly (id uuid primary key references objects(id) on delete cascade on update cascade, friendly varchar not null unique);
		create index idx_friendly on pr_friendly (friendly);
		`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
		// TODO compute projection for existing objects!
		stmt = `insert into meta (key, value) values ("module_friendlyid_version", "initial");`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	case "initial":
	default:
		return errors.New(fmt.Sprintf("FriendlyId schema version unknown: %v", schemaVersion))
	}
	return nil
}

func (ModuleOwner) Init(db *sql.DB) error {
	var schemaVersion string = "empty"
	if err := queryMeta(db, "module_owner_version", &schemaVersion); err != nil {
		return err
	}
	switch schemaVersion {
	case "empty":
		stmt := `
		drop index if exists idx_owner;
		drop table if exists pr_owner;
		create table pr_owner (id uuid primary key references objects(id) on delete cascade on update cascade, owner uuid references objects (id) on update cascade);
		create index idx_owner on pr_owner (owner);
		`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
		// TODO compute projection for existing objects!
		stmt = `insert into meta (key, value) values ("module_owner_version", "initial");`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	case "initial":
	default:
		return errors.New(fmt.Sprintf("Workspace schema version unknown: %v", schemaVersion))
	}
	return nil
}

func (ModuleJobs) Init(db *sql.DB) error {
	var schemaVersion string = "empty"
	if err := queryMeta(db, "module_jobs_version", &schemaVersion); err != nil {
		return err
	}
	switch schemaVersion {
	case "empty":
		stmt := `
		drop table if exists pr_job;
		create table pr_job (id uuid primary key references objects(id) on delete cascade on update cascade, target uuid references objects (id) on delete cascade on update cascade unique);
		`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
		// TODO compute projection for existing objects!
		stmt = `insert into meta (key, value) values ("module_jobs_version", "initial");`
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	case "initial":
	default:
		return errors.New(fmt.Sprintf("Workspace schema version unknown: %v", schemaVersion))
	}
	return nil
}
