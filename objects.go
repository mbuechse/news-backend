// copyright Matthias Büchse, 2019
package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type object map[string]interface{}
type objectMap map[string]object
type referenceChannel chan string
type prefetchMap map[string]string

type ObjectError struct{ obj object }

func (err ObjectError) Error() string {
	return err.obj["msg"].(string)
}

const (
	TYPE_ACCOUNT = "account"
	TYPE_EVENT   = "event"
	TYPE_MATVIEW = "matview"
	TYPE_ERROR   = "ERROR"
	K_ID         = "id"
	K_VERSION    = "version"
	K_TYPE       = "type"
	K_STATE      = "state"
	EACCES       = 403
	ENOENT       = 404
)

type queryable interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

func transformToError(obj object, code int, text string) object {
	log.Println("transforming to error", obj, code, text)
	// debug.PrintStack()
	for k := range obj {
		if k != K_ID {
			delete(obj, k)
		}
	}
	obj[K_TYPE] = TYPE_ERROR
	obj["code"] = code
	obj["msg"] = text
	return obj
}

func (obj object) extractError() error {
	if obj[K_TYPE] == TYPE_ERROR {
		return ObjectError{obj}
	}
	return nil
}

func (objects objectMap) extractError() error {
	for _, obj := range objects {
		if err := obj.extractError(); err != nil {
			return err
		}
	}
	return nil
}

func computeVersionString() string {
	return "+" + strconv.FormatInt(time.Now().Unix(), 10)
}

func checkReference(element interface{}, references referenceChannel) error {
	switch vv := element.(type) {
	case string:
		references <- vv
	case []string: // happens when we generate elements procedurally
		for _, e := range vv {
			if err := checkReference(e, references); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, e := range vv {
			if err := checkReference(e, references); err != nil {
				return err
			}
		}
	default:
		return errors.New(fmt.Sprintf("invalid reference type: %v", element))
	}
	return nil
}

func checkElement(element interface{}, includeMarked bool, references referenceChannel) error {
	var err error
	switch vv := element.(type) {
	case object:
		for k, v := range vv {
			if strings.HasPrefix(k, "$") {
				if includeMarked || !strings.HasSuffix(k, "?") {
					err = checkReference(v, references)
				}
			} else {
				err = checkElement(v, includeMarked, references)
			}
			if err != nil {
				return err
			}
		}
	case []interface{}:
		for _, v := range vv {
			if err = checkElement(v, includeMarked, references); err != nil {
				return err
			}
		}
	case bool:
	case string:
	case json.Number:
	case int: // happens when we generate elements procedurally
	default:
		log.Printf("not processing %#v", element)
	}
	return nil
}

func (objects objectMap) checkObject(obj object) (id string, err error) {
	id, ok := obj["id"].(string)
	if !ok {
		return "", errors.New(fmt.Sprintf("id field is not a string: %v", obj))
	}
	references := make(referenceChannel, 1)
	errorChan := make(chan error, 1)
	errorColl := make([]string, 0)
	go func() { errorChan <- checkElement(obj, true, references); close(references) }()
	for ref := range references {
		if _, present := objects[ref]; !present {
			errorColl = append(errorColl, ref)
		}
	}
	err = <-errorChan
	if err != nil {
		return "", err
	}
	if len(errorColl) != 0 {
		return "", errors.New(fmt.Sprintf("invalid references: %v", errorColl))
	}
	return id, nil
}

func (objects objectMap) computePrefetchInner(prefetch *[]string, pm prefetchMap, obj object) (err error) {
	references := make(referenceChannel, 1)
	errorChan := make(chan error, 1)
	errorColl := make([]error, 0)
	go func() { errorChan <- checkElement(obj, false, references); close(references) }()
	for ref := range references {
		obj := objects[ref]
		id := obj["id"].(string)
		version, _ := obj["version"].(string)
		if _, present := pm[id]; !present {
			pm[id] = version
			if err = objects.computePrefetchInner(prefetch, pm, obj); err != nil {
				errorColl = append(errorColl, err)
			}
			*prefetch = append(*prefetch, fmt.Sprintf("%v:%v", id, version))
		}
	}
	if err = <-errorChan; err != nil {
		return err
	}
	if len(errorColl) != 0 {
		return errors.New(fmt.Sprintf("Errors have occured: %v", errorColl))
	}
	return nil
}

func UuidBase64(guid uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString(guid[:])
}

func Sum256Base64(s []byte) string {
	hash := sha256.Sum256(s)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func Sum256Hex(s []byte) string {
	hash := sha256.Sum256(s)
	return hex.EncodeToString(hash[:])
}

func Sum256HexPrefix(s []byte) string {
	hash := sha256.Sum256(s)
	return hex.EncodeToString(hash[:8])
}

func (objects objectMap) ComputePrefetch(obj object) error {
	prefetchMap := make(prefetchMap)
	prefetch := make([]string, 0)
	if err := objects.computePrefetchInner(&prefetch, prefetchMap, obj); err != nil {
		return err
	}
	prefetchSorted := make([]string, len(prefetch))
	copy(prefetchSorted, prefetch)
	sort.Strings(prefetchSorted)
	prefetchString := strings.Join(prefetchSorted, "\n")
	obj["$prefetch"] = prefetch
	obj["version"] = Sum256HexPrefix([]byte(prefetchString))
	return nil
}

func QueryExistence(db queryable, keys map[string]bool) error {
	if len(keys) == 0 {
		return nil
	}
	keys2 := make([]interface{}, len(keys))
	i := 0
	for key := range keys {
		keys2[i] = key
		i++
	}
	rows, err := db.Query("select id from objects where id in (?"+strings.Repeat(",?", len(keys)-1)+")", keys2...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		delete(keys, id)
	}
	return rows.Err()
}

func (objects objectMap) consumeRows(rows *sql.Rows, limit int, keys *[]string) error {
	keyz := make([]string, limit)
	j := 0
	for rows.Next() {
		var id string
		var data []byte
		var o map[string]interface{}
		if err := rows.Scan(&id, &data); err != nil {
			return err
		}
		keyz[j] = id
		j++
		if _, present := objects[id]; present {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&o); err != nil {
			return err
		}
		// id := o["id"].(string)
		objects[id] = o
	}
	if keys != nil {
		if j == 0 && *keys == nil {
			*keys = []string{}
		} else {
			*keys = append(*keys, keyz[:j]...)
		}
	}
	return rows.Err()
}

func (objects objectMap) queryByKeys(db *sql.DB, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	// go specialty: convert from []string to []interface{}
	keys2 := make([]interface{}, len(keys))
	for i, key := range keys {
		keys2[i] = key
	}
	sqlStmt := "select id, data from objects where id in (?" + strings.Repeat(",?", len(keys)-1) + ")"
	log.Println(sqlStmt, keys2)
	rows, err := db.Query(sqlStmt, keys2...)
	if err != nil {
		return err
	}
	defer rows.Close()
	return objects.consumeRows(rows, len(keys), nil)
}

func (objects objectMap) queryByFriendly(db *sql.DB, fkeys []string, keys *[]string) error {
	if len(fkeys) > 32 {
		for i := 0; i < len(fkeys); {
			j := i + 32
			if j > len(fkeys) {
				j = len(fkeys)
			}
			if err := objects.queryByFriendly(db, fkeys[i:j], keys); err != nil {
				return err
			}
			i = j
		}
	}
	if len(fkeys) == 0 {
		return nil
	}
	// go specialty: convert from []string to []interface{}
	keys2 := make([]interface{}, len(fkeys))
	for i, key := range fkeys {
		keys2[i] = key
	}
	sqlStmt := "select id, data from objects natural join pr_friendly where friendly in (?" + strings.Repeat(",?", len(fkeys)-1) + ")"
	log.Println(sqlStmt, keys2)
	rows, err := db.Query(sqlStmt, keys2...)
	if err != nil {
		return err
	}
	defer rows.Close()
	return objects.consumeRows(rows, len(fkeys), keys)
}

func (objects objectMap) queryDB(db *sql.DB, clauses string, limit int, keys *[]string, args ...interface{}) error {
	args = append(args, limit)
	sqlStmt := `select id, data from objects ` + clauses + ` limit ?`
	log.Println(sqlStmt, args)
	rows, err := db.Query(sqlStmt, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	return objects.consumeRows(rows, limit, keys)
}

func CollectReferences(objects []object, includeMarked bool, references map[string]bool) error {
	errChan := make(chan error, 1)
	refChan := make(referenceChannel, 3)
	go func() {
		var err error = nil
		for _, o := range objects {
			err = checkElement(o, includeMarked, refChan)
			if err != nil {
				break
			}
		}
		errChan <- err
		close(refChan)
	}()
	for ref := range refChan {
		references[ref] = true
	}
	return <-errChan
}

const (
	NOFOLLOW   = 0
	FOLLOW     = 1
	FOLLOWDEEP = 2
	FOLLOWMASK = 3
)

func (objects objectMap) loadFromDatabase(db *sql.DB, keys []string, misses map[string]bool, follow int) error {
	references := make(map[string]bool)
	for _, key := range keys {
		references[key] = true
	}
	for len(references) != 0 {
		queryKeys := make([]string, 0, len(references))
		for k := range references {
			if _, present := objects[k]; !present && !misses[k] {
				queryKeys = append(queryKeys, k)
			}
		}
		if err := objects.queryByKeys(db, queryKeys); err != nil {
			return err
		}
		for _, k := range queryKeys {
			if _, present := objects[k]; !present {
				misses[k] = true
			}
		}
		if follow == NOFOLLOW {
			break
		}
		checkObjects := make([]object, 0, len(references))
		for k := range references {
			if !misses[k] {
				checkObjects = append(checkObjects, objects[k])
			}
		}
		if err := CollectReferences(checkObjects, follow >= FOLLOWDEEP, references); err != nil {
			return err
		}
		for _, o := range checkObjects {
			delete(references, o["id"].(string))
		}
		for k := range misses {
			delete(references, k)
		}
	}
	return nil
}
