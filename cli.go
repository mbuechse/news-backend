// copyright Matthias Büchse, 2019
package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	cmap "github.com/orcaman/concurrent-map"
	"golang.org/x/crypto/bcrypt"
)

type DatabaseApp struct {
	dbPath      string
	db          *sql.DB
	matViewsMux sync.Mutex
	matViewsMap map[int]cmap.ConcurrentMap // per access level
	module      Module
	inter       Inter
	secret      []byte
	jobQueue    chan object
	imgPath     string
	imgPaths    map[int]string
}

type Transformer interface {
	transform(object)
}

type Claims struct {
	jwt.StandardClaims
	PrivilegeLevel int    `json:"prl,omitempty"`
	AccountId      string `json:"sid,omitempty"`
}

type Authorization struct {
	level   int
	subject string
	id      string
}

type AuthorizedApp struct {
	*DatabaseApp
	auth        *Authorization
	matViews    cmap.ConcurrentMap
	transformer Transformer
}

const (
	GUEST   = 9 // will see reduced data
	PREMIUM = 8 // will see full data w/o personal data
	EDITOR  = 4 // will see full data, can change content within sensible boundaries
	CHIEF   = 3 // editor-in-chief
	ADMIN   = 1 // ???
	ROOT    = 0 // will see full data, can change almost anything
)

var PRIVILEGES = map[string]int{
	"guest":   GUEST,
	"premium": PREMIUM,
	"editor":  EDITOR,
	"chief":   CHIEF,
	"admin":   ADMIN,
	"root":    ROOT,
}

var RESOLUTIONS []int = []int{100, 400, 720}

const QUALITY = 75

func NewDatabaseApp(dbPath string, module Module, inter Inter, secret []byte, imgPath string) (*DatabaseApp, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	if err := module.Init(db); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Join(imgPath, "full"), 0755); err != nil {
		return nil, err
	}

	imgPaths := make(map[int]string, len(RESOLUTIONS))
	for _, res := range RESOLUTIONS {
		p := filepath.Join(imgPath, strconv.Itoa(res))
		if err := os.MkdirAll(p, 0755); err != nil {
			return nil, err
		}
		imgPaths[res] = p
	}

	return &DatabaseApp{dbPath: dbPath, db: db, matViewsMap: make(map[int]cmap.ConcurrentMap), module: module, inter: inter, secret: secret, jobQueue: make(chan object, 5), imgPath: imgPath, imgPaths: imgPaths}, nil
}

func (app *DatabaseApp) Close() {
	app.db.Close()
}

type NullTransformer struct{}
type DefaultTransformer struct {
	inner Transformer
	auth  *Authorization
}
type GuestTransformer struct {
	inner         Transformer
	now           int64
	versionSuffix string
}

func (NullTransformer) transform(obj object) {
	if obj[K_TYPE] == TYPE_ERROR {
		return
	}
	version, _ := obj[K_VERSION].(string) // "" if not present
	obj[K_VERSION] = version
}

func (t DefaultTransformer) transform(obj object) {
	t.inner.transform(obj)
	id, _ := obj[K_ID].(string)
	if t.auth.level > EDITOR && (strings.HasPrefix(id, "/query/")) {
		// transform a potential 404 into 401, so the matview doesn't even get computed
		transformToError(obj, EACCES, fmt.Sprintf("access to sensitive information denied; user '%v'", t.auth.id))
	}
	typ, _ := obj[K_TYPE].(string)
	if typ == TYPE_ERROR {
		return
	}
	visibility, _ := obj["visibility"].(string)
	if level, present := PRIVILEGES[visibility]; present && t.auth.level > level {
		transformToError(obj, EACCES, "access denied")
	}
	owner, _ := obj["$owner"].(string)
	if t.auth.level > EDITOR && owner != "" {
		transformToError(obj, EACCES, fmt.Sprintf("access to sensitive information denied; user '%v'", t.auth.id))
	}
	if t.auth.level >= EDITOR && typ == TYPE_ACCOUNT && id != t.auth.id {
		// do not modify version
		// a) We shall always, ALWAYS redact personal data over this API, so no distinction necessary.
		// b) It would make a lot of trouble in postprocessing $prefetch.
		// 	obj[K_VERSION] = obj[K_VERSION].(string) + t.redactedVersionSuffix
		transformToError(obj, EACCES, fmt.Sprintf("access to sensitive information denied; user '%v'", t.auth.id))
	}
}

const THRESHOLD = 30 * 24 * 3600 // 1 month

func (t GuestTransformer) transform(obj object) {
	t.inner.transform(obj)
	if obj[K_TYPE] == TYPE_ERROR {
		return
	}
	version := obj[K_VERSION].(string)
	split := strings.Split(version, "/")
	if len(split) > 1 && split[1] == "pruned" {
		return
	}
	obj[K_VERSION] = split[0] + "/pruned/" + t.versionSuffix
	datestr, _ := obj["date"].(string)
	date, err := strconv.Atoi(datestr)
	if err != nil || t.now-int64(date) > THRESHOLD {
		typ := obj[K_TYPE]
		if typ == TYPE_EVENT {
			obj["$components"] = []interface{}{}
			obj["pruned"] = true
		} else if typ == "statement" {
			obj["content"] = "(nicht in freier Version enthalten)"
			obj["pruned"] = true
		}
	}
}

func (app *DatabaseApp) MatViewsForLevel(level int) cmap.ConcurrentMap {
	app.matViewsMux.Lock()
	defer app.matViewsMux.Unlock()
	// collapse levels a bit for the matview cache... let's hope that's okay
	if level >= ADMIN && level < PREMIUM {
		level = PREMIUM
	}
	mv, present := app.matViewsMap[level]
	if !present {
		mv = cmap.New()
		app.matViewsMap[level] = mv
	}
	return mv
}

func (app *DatabaseApp) MatViewsMapCopy() map[int]cmap.ConcurrentMap {
	app.matViewsMux.Lock()
	defer app.matViewsMux.Unlock()
	result := make(map[int]cmap.ConcurrentMap, len(app.matViewsMap))
	for level, m := range app.matViewsMap {
		result[level] = m
	}
	return result
}

func (app *DatabaseApp) InvalidateMatViews() {
	app.matViewsMux.Lock()
	defer app.matViewsMux.Unlock()
	app.matViewsMap = make(map[int]cmap.ConcurrentMap)
}

func (app *AuthorizedApp) Transformer() Transformer {
	if app.transformer == nil {
		var transformer Transformer = DefaultTransformer{NullTransformer{}, app.auth}
		if false && app.auth.level >= GUEST {
			// ^^ deactivated for the time being (only impedes alpha testing phase)
			t := time.Now()
			versionSuffix := fmt.Sprintf("%04d%02d%02d", t.Year(), t.Month(), t.Day())
			transformer = GuestTransformer{transformer, t.Unix(), versionSuffix}
		}
		app.transformer = transformer
	}
	return app.transformer
}

func (app *DatabaseApp) loadAccount(email string) (result object) {
	objects := make(objectMap)
	_ = objects.queryDB(app.db, `natural join pr_email where email = ?`, 1, nil, email)
	for _, obj := range objects {
		return obj
	}
	return object{}
}

const EXTRACT = 4 // extract errors

func (app *AuthorizedApp) loadFromDatabase(objects objectMap, keys []string, flags int) error {
	misses := make(map[string]bool)
	err := objects.loadFromDatabase(app.db, keys, misses, flags&FOLLOWMASK)
	if err == nil {
		for k := range misses {
			objects[k] = transformToError(object{K_ID: k}, ENOENT, "object not found")
		}
		t := app.Transformer()
		for _, o := range objects {
			t.transform(o)
		}
		if flags&EXTRACT != 0 {
			err = objects.extractError()
		}
	}
	return err
}

func (app *AuthorizedApp) queryDB(objects objectMap, clauses string, limit int, keys *[]string, args ...interface{}) error {
	err := objects.queryDB(app.db, clauses, limit, keys, args...)
	if err == nil {
		t := app.Transformer()
		for _, k := range *keys {
			t.transform(objects[k])
		}
	}
	return err
}

func (app *AuthorizedApp) computePreView(objects objectMap, k string) (mv object) {
	targetId := ""
	err := fmt.Errorf("invalid preview identifier: %v", k)
	split := strings.Split(k, "/")
	if split[0] != "" || len(split) < 2 {
		// keep err unchanged
	} else if len(split) == 3 && split[1] == "preview" {
		targetId = split[2]
		// !!! do not use EXTRACT here because objects could be tainted from the get go
		// instead, handle direct errors below with the type distinction
		err = app.loadFromDatabase(objects, []string{targetId}, FOLLOW)
	}
	if err == nil {
		obj := objects[targetId]
		if obj[K_TYPE] == "event" {
			mv = object{
				K_TYPE:     "event-preview",
				K_ID:       k,
				"$target?": targetId,
			}
			for okey, oval := range obj {
				if okey != K_TYPE && okey != K_ID && okey != "$components" {
					mv[okey] = oval
				}
			}
			if components, ok := obj["$components"].([]interface{}); ok {
				cs := make([]interface{}, len(components))
				for i, cid := range components {
					if cidstr, ok := cid.(string); ok {
						com := objects[cidstr]
						cs[i] = object{
							"$target?": cid,
							"$tags":    com["$tags"],
						}
					}
				}
				mv["components"] = cs
			}
		} else if obj[K_TYPE] == TYPE_ERROR {
			mv = object{
				K_TYPE:     TYPE_ERROR,
				K_ID:       k,
				"code":     obj["code"],
				"msg":      obj["msg"],
				"$target?": targetId,
			}
		} else {
			err = fmt.Errorf("Invalid object type for preview '%v': %v", k, obj)
		}
	}
	if err == nil {
		app.Transformer().transform(mv)
		return mv
	}
	return transformToError(object{K_ID: k}, 500, err.Error())
}

func (app *AuthorizedApp) getPreView(objects objectMap, k string) object {
	if mv, present := app.matViews.Get(k); present {
		return mv.(object)
	}
	mv := app.computePreView(objects, k)
	if mv[K_TYPE] != TYPE_ERROR {
		app.matViews.Set(k, mv)
	}
	return mv
}

func (app *AuthorizedApp) computeMatView(objects objectMap, k string) (mv object) {
	var objectKeys []string
	preview := false
	err := fmt.Errorf("invalid matview identifier: %v", k)
	split := strings.Split(k, "/")
	if split[0] != "" || len(split) < 2 {
		// keep err unchanged
	} else if len(split) == 2 && split[1] == "home" {
		clauses := `natural join pr_date where type = ? order by date desc`
		err = app.queryDB(objects, clauses, 50, &objectKeys, TYPE_EVENT)
		preview = true
	} else if len(split) >= 3 && split[1] == "query" && strings.HasPrefix(split[2], "owner=") {
		accountId := split[2][6:]
		if accountId != app.auth.id {
			err = fmt.Errorf("access denied to '%v'; user '%v'", k, app.auth.id)
		} else if len(split) == 3 {
			clauses := `natural join pr_owner where owner = ?`
			err = app.queryDB(objects, clauses, 100, &objectKeys, accountId)
		}
	} else if len(split) == 4 && split[1] == "latest" && strings.HasPrefix(split[2], "type=") && strings.HasPrefix(split[3], "tag=") {
		typeStr := split[2][5:]
		tagStr := split[3][4:]
		clauses := `natural join pr_date natural join pr_tags where type = ? and tagid = ? order by date desc`
		err = app.queryDB(objects, clauses, 20, &objectKeys, typeStr, tagStr)
	}
	if err == nil {
		err = app.loadFromDatabase(objects, objectKeys, FOLLOW)
	}
	if err == nil {
		i := 0
		for j, key := range objectKeys {
			okey := objectKeys[j]
			var obj object
			if preview {
				okey = "/preview/" + okey
				obj = app.getPreView(objects, okey)
				objects[okey] = obj
			} else {
				obj = objects[key]
			}
			if obj["type"] != TYPE_ERROR {
				objectKeys[i] = okey
				i++
			}
		}
		mv = object{
			K_TYPE:     TYPE_MATVIEW,
			K_ID:       k,
			"$objects": objectKeys[:i],
		}
		if i != len(objectKeys) {
			mv["numErrors"] = len(objectKeys) - i
		}
		err = objects.ComputePrefetch(mv)
	}
	if err == nil {
		app.Transformer().transform(mv)
		return mv
	}
	return transformToError(object{K_ID: k}, 500, err.Error())
}

func (app *AuthorizedApp) handleView(objects objectMap, k string) {
	if !strings.HasPrefix(k, "/") {
		return
	}
	if mv, present := app.matViews.Get(k); present {
		objects[k] = mv.(object)
		return
	}
	log.Printf("cache miss (level %v): %v", app.auth.level, k)
	var mv object
	if strings.HasPrefix(k, "/preview/") {
		mv = app.computePreView(objects, k)
	} else {
		mv = app.computeMatView(objects, k)
	}
	if mv[K_TYPE] != TYPE_ERROR && !strings.HasPrefix(k, "/query/") {
		app.matViews.Set(k, mv)
	}
	objects[k] = mv
}

func (app *AuthorizedApp) checkVersion(obj object) error {
	version, ok := obj[K_VERSION].(string)
	if !ok {
		return nil
	}
	split := strings.Split(version, "/")
	if len(split) == 1 {
		return nil
	}
	return errors.New(fmt.Sprintf("Invalid version '%v' for object: %v", version, obj))
}

var editorCanChange map[string]bool = map[string]bool{
	"component": true, "event": true, "book": true, "statistic": true, "statement": true,
}

// Any user can change any object they own, as well as their account.
// In addition, an editor can change any object that doesn't have an owner if its type is in editorCanChange.
// In addition, a ROOT level user can change any object.
func (app *AuthorizedApp) checkOwner(extant, obj object) error {
	if app.auth.level == ROOT || extant[K_ID] == app.auth.id {
		return nil
	}
	if owner, ok := extant["$owner"].(string); ok {
		if owner == app.auth.id {
			return nil
		}
	} else if app.auth.level <= EDITOR {
		if editorCanChange[extant[K_TYPE].(string)] {
			return nil
		}
	}
	return errors.New(fmt.Sprintf("Invalid owner (current user '%v'): %v", app.auth.id, extant))
}

// The privilege level of an account must be set, and it must not be higher than that of the current user.
func (app *AuthorizedApp) checkPrivilege(obj object) error {
	if obj[K_TYPE] != TYPE_ACCOUNT || app.auth.level == ROOT {
		return nil
	}
	privilege, _ := obj["privilege"].(string)
	if level, present := PRIVILEGES[privilege]; present {
		if obj[K_ID] == app.auth.id && level >= app.auth.level {
			return nil
		}
		// XXX Do we want people to be able to promote others to their own level? Or should this be left to superiors?
		if level > app.auth.level {
			return nil
		}
	}
	return errors.New(fmt.Sprintf("Invalid privilege level '%v' (current user '%v'): %v", privilege, app.auth.id, obj))
}

func (app *AuthorizedApp) checkTypeChange(extant, obj object) error {
	v0, _ := extant[K_TYPE].(string)
	v1, _ := obj[K_TYPE].(string)
	if app.auth.level == ROOT || v0 == v1 {
		return nil
	}
	return errors.New(fmt.Sprintf("Invalid type change for '%v' from '%v' to '%v'", obj[K_ID], v0, v1))
}

func (app *AuthorizedApp) doUpsert(tx *sql.Tx, obj object, prevVersion interface{}) (err error) {
	id, ok := obj["id"].(string)
	if !ok {
		// TODO   || !sanitizeId(&id)
		// FIXME id should be uuid conformant, but definitely no slashes in id (reserved for materialized views)
		return BadRequest{fmt.Errorf("invalid id in object: %v", obj)}
	}
	objects := make(objectMap)
	var rows *sql.Rows
	rows, err = tx.Query(`select id, data from objects where id = ?`, id)
	if err != nil {
		return err
	}
	if err := objects.consumeRows(rows, 1, nil); err != nil {
		return err
	}
	// sanity checks
	references := make(map[string]bool)
	if err := CollectReferences([]object{obj}, true, references); err != nil {
		return err
	}
	delete(references, id) // reference yourself if you must
	if err := QueryExistence(tx, references); err != nil {
		return err
	}
	if len(references) != 0 {
		return BadRequest{errors.New(fmt.Sprintf("Unsatisfied references for '%v': %v", id, references))}
	}
	mtx := app.module.Begin(tx)
	defer mtx.Close()
	if err := app.checkVersion(obj); err != nil {
		return err
	}
	if err := app.checkPrivilege(obj); err != nil {
		return err
	}
	if extant, present := objects[id]; present {
		if prevVersion != "*" && prevVersion != extant[K_VERSION] && obj[K_VERSION] != extant[K_VERSION] {
			return PreconditionFailed{fmt.Errorf("Version did not match: '%v' != '%v'", prevVersion, extant[K_VERSION])}
		}
		if err := app.checkOwner(extant, obj); err != nil {
			return err
		}
		if err := app.checkTypeChange(extant, obj); err != nil {
			return err
		}
		if err := mtx.Update(objects, obj); err != nil {
			return err
		}
		objects[id] = obj
	} else {
		if prevVersion != "*" && prevVersion != "ENOENT" {
			return PreconditionFailed{fmt.Errorf("Version did not match: '%v' != 'ENOENT'", prevVersion)}
		}
		// FIXME what kind of objects may be created by whom? Current `upsert` endpoint is only available for EDITOR and better anyway...
		if err := mtx.Insert(obj); err != nil {
			return err
		}
	}
	return nil
}

func (app *AuthorizedApp) doDelete(tx *sql.Tx, id string) (err error) {
	mtx := app.module.Begin(tx)
	defer mtx.Close()
	if err := mtx.Delete(id); err != nil {
		return err
	}
	return nil
}

func (app *AuthorizedApp) Get(keys ...string) (result []map[string]interface{}, err error) {
	objects := make(objectMap)
	trueKeys := make([]string, len(keys))
	j := 0
	for _, key := range keys {
		trueKey := strings.Split(key, ":")[0]
		if strings.HasPrefix(trueKey, "/") {
			app.handleView(objects, trueKey)
		} else {
			trueKeys[j] = trueKey
			j++
		}
	}
	if j > 0 {
		if err := app.loadFromDatabase(objects, trueKeys[:j], NOFOLLOW); err != nil {
			return nil, err
		}
	}
	result = make([]map[string]interface{}, len(keys))
	j = 0
	for _, key := range keys {
		split := strings.Split(key, ":")
		o := objects[split[0]]
		if err := o.extractError(); err != nil {
			return nil, err
		}
		if len(split) < 2 || o[K_VERSION] != split[1] {
			result[j] = o
			j++
		}
	}
	return result[:j], nil
}

func downloadIntoWriter(url string, wr io.Writer) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(wr, resp.Body)
	return err
}

func downloadIntoTemp(url, target string) (fname string, typ string, err error) {
	var f *os.File
	f, err = ioutil.TempFile(filepath.Dir(target), "download_*")
	if err != nil {
		return
	}
	defer f.Close()
	if err = downloadIntoWriter(url, f); err != nil {
		return
	}
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return
	}
	_, typ, err = image.DecodeConfig(f)
	if err != nil {
		return
	}
	return f.Name(), typ, nil
}

func shrinkImage(src, tgt, final string, edgeLength int, quality int) error {
	cmd := exec.Command("convert", src, "-resize", fmt.Sprintf("%vx%v^>", edgeLength, edgeLength), "-strip", "-quality", fmt.Sprintf("%v", quality), tgt)
	log.Printf("Running command: %v", cmd.Args)
	if err := cmd.Run(); err != nil {
		return err
	}
	if strings.HasSuffix(tgt, ".png") {
		cmd := exec.Command("optipng", tgt)
		log.Printf("Running command: %v", cmd.Args)
		// out, err := cmd.CombinedOutput(); log.Println(string(out))
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	ti, err := os.Stat(tgt)
	if err != nil {
		return err
	}
	if final != "" && 10*ti.Size() >= 9*si.Size() {
		log.Printf("convert did not save a lot (%v -> %v); symlinking instead...", si.Size(), ti.Size())
		if err := os.Remove(tgt); err != nil {
			return err
		}
		if err := os.Symlink(final, tgt); err != nil {
			return err
		}
	}
	return nil
}

func ensureDir(path string) error {
	if err := os.Mkdir(path, 0755); err != nil {
		if err.(*os.PathError).Err.(syscall.Errno) != syscall.EEXIST {
			return err
		}
	}
	return nil
}

func (app *DatabaseApp) checkImage(obj object) error {
	imageUrl, ok := obj["imageUrl"].(string)
	if !ok || imageUrl == "" {
		return nil
	}
	imageHash, ok := obj["imageHash"].(string)
	if !ok {
		imageHash = ""
	}
	if i := strings.Index(imageHash, ":"); i != -1 {
		imageHash = imageHash[i+1:]
	}
	computedHash := Sum256Hex([]byte(imageUrl))
	if imageHash == computedHash {
		return nil
	}
	fullDir := filepath.Join(app.imgPath, "full", computedHash[:2])
	if err := ensureDir(fullDir); err != nil {
		return err
	}
	tmpName, typ, err := downloadIntoTemp(imageUrl, fullDir)
	if err != nil {
		return err
	}
	imgType := ".jpg"
	if typ == "png" {
		cmd := exec.Command("optipng", tmpName)
		log.Printf("Running command: %v", cmd.Args)
		if err := cmd.Run(); err != nil {
			return err
		}
		imgType = ".png"
	}
	final := filepath.Join(fullDir, computedHash+imgType)
	for res, path := range app.imgPaths {
		resDir := filepath.Join(path, computedHash[:2])
		if err := ensureDir(resDir); err != nil {
			return err
		}
		tgt := filepath.Join(resDir, computedHash+imgType)
		relFinal, err := filepath.Rel(resDir, final)
		if err != nil {
			return err
		}
		if err := shrinkImage(tmpName, tgt, relFinal, res, QUALITY); err != nil {
			return err
		}
	}
	if err := os.Rename(tmpName, final); err != nil {
		return err
	}
	obj["imageHash"] = imgType[1:] + ":" + computedHash
	return nil
}

func (app *AuthorizedApp) processRun(job object) error {
	target := job["$target"].(string)
	objects := make(objectMap)
	// NOFOLLOW because we don't want to load scratchpad's $references, and even less so with a Transformer
	if err := app.loadFromDatabase(objects, []string{target}, NOFOLLOW|EXTRACT); err != nil {
		return err
	}
	scratchpad := objects[target]
	if scratchpad[K_VERSION] != job["tVersion"] {
		return fmt.Errorf("Target version does not equal current version of target: %v != %v", job["tVersion"], scratchpad[K_VERSION])
	}
	scratchpadRef := scratchpad["$references"].([]interface{})
	scratchpadRefSet := make(map[string]bool, len(scratchpadRef))
	for _, ref := range scratchpadRef {
		scratchpadRefSet[ref.(string)] = true
	}
	content := scratchpad["content"].(string)
	contentLines := strings.Split(content, "\n")
	remarks := New()
	ods := parseInter(contentLines, remarks)
	if err := applyToObjects(app.db, ods, objects, remarks, "ENOENT"); err != nil {
		return err
	}
	// check images and tags, count privileged objects
	numPrivileged := 0
	for _, od := range ods {
		obj := objects[od.initial[1]]
		if err := app.checkImage(obj); err != nil {
			remarks.AddError(od.start, err.Error())
		}
		if tags, ok := obj["$tags"].([]interface{}); ok {
			if obj["type"] == "statement" && len(tags) < 2 {
				remarks.AddHint(od.start, "statement has less than two tags, consider adding tags")
			}
		}
		if _, present := obj["visibility"]; present {
			numPrivileged++
		}
	}
	// commit stuff to db if no errors occurred and we aren't just checking
	tx, err := app.db.Begin()
	if err != nil {
		return err
	}
	inv := make(map[string]bool, 10*len(ods))
	datestr := time.Now().Format("2006-01-02 15:04:05")
	if job["instruction"] != "check" && remarks.Severity() < ERROR {
		newVersion := computeVersionString()
		for _, od := range ods {
			obj := objects[od.initial[1]]
			prevVersion := obj[K_VERSION]
			obj[K_VERSION] = newVersion
			if err := app.doUpsert(tx, obj, prevVersion); err != nil {
				// !!! do not roll back just yet !!!
				remarks.AddError(od.start, err.Error())
			}
			typ := obj[K_TYPE].(string)
			// invalidate /latest/type=TYPE/tag=TAG
			if ts, ok := obj["$tags"].([]interface{}); ok {
				for _, t := range ts {
					inv[fmt.Sprintf("/latest/type=%v/tag=%v", typ, t.(string))] = true
				}
			}
			// invalidate /home if TYPE == event
			// invalidate /preview/ID if TYPE == event
			if typ == "event" {
				inv["/home"] = true
				inv[fmt.Sprintf("/preview/%v", od.initial[1])] = true
			}
			if !scratchpadRefSet[od.initial[1]] {
				scratchpadRef = append(scratchpadRef, od.initial[1])
				scratchpadRefSet[od.initial[1]] = true
			}
		}
		if remarks.Severity() < ERROR {
			remarks.AddInfo(-2, "[%v] successfully upserted %v object(s)", datestr, len(ods))
		} else {
			// !!! we encountered problems for some objects, so rollback everything
			tx.Rollback()
			// FIXME clear inv...
			// and start new transaction for we still want to save the scratchpad
			tx, err = app.db.Begin()
			if err != nil {
				return err
			}
		}
	} else {
		errors := remarks.Histo(ERROR)
		info := remarks.Histo(INFO) + remarks.Histo(HINT)
		if errors > 0 {
			remarks.AddInfo(-2, "[%v] Finished with %v error(s); see below", datestr, errors)
		} else if info > 0 {
			remarks.AddInfo(-2, "[%v] Finished with %v hint(s); see below", datestr, info)
		} else {
			remarks.AddInfo(-2, "[%v] Finished successfully!", datestr)
		}
	}
	if numPrivileged != 0 {
		remarks.AddHint(-1, "objects with explicit visibility: %d", numPrivileged)
	}
	content = remarks.Embed(contentLines)
	scratchpad[K_VERSION] = computeVersionString()
	scratchpad["content"] = content
	scratchpad["$references"] = scratchpadRef
	if err := app.doUpsert(tx, scratchpad, job["tVersion"].(string)); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if len(inv) != 0 {
		log.Println("Invalidating material views:", inv)
		matViewsMap := app.MatViewsMapCopy()
		for level, m := range matViewsMap {
			l0 := m.Count()
			for i := range inv {
				m.Remove(i)
			}
			l1 := m.Count()
			log.Printf("Deleted %v entries on level %v (%v remaining)", l0-l1, level, l1)
		}
	}
	// adjust target version so the job is still recognized as "up to date"
	job["tVersion"] = scratchpad[K_VERSION]
	if remarks.Severity() == ERROR {
		return fmt.Errorf("[%v] errors occurred during run, see scratchpad", datestr)
	}
	return nil
}

func authFromAccount(account object) (*Authorization, error) {
	id := account["id"].(string)
	privilege, _ := account["privilege"].(string)
	level, present := PRIVILEGES[privilege]
	if !present {
		return nil, fmt.Errorf("Invalid privilege level: %v", account["privilege"])
	}
	return &Authorization{level: level, id: id, subject: account["email"].(string)}, nil
}

func Authorize(app *DatabaseApp, auth *Authorization) *AuthorizedApp {
	return &AuthorizedApp{app, auth, app.MatViewsForLevel(auth.level), nil}
}

func (app *AuthorizedApp) processJobInner(job object) {
	// catch any programming errors that lead to a panic to ensure that the job object can be updated properly
	defer func() {
		if err := recover(); err != nil {
			job["error"] = fmt.Sprintf("%v", err)
			job[K_STATE] = "failed"
			log.Printf("job '%v' failed: %v", job[K_ID], err)
		} else {
			log.Printf("done processing job: %v", job)
		}
	}()

	var suAuth *Authorization
	accountId := job["$owner"].(string)
	objects := make(objectMap)
	err := app.loadFromDatabase(objects, []string{accountId}, FOLLOW|EXTRACT)
	if err == nil {
		suAuth, err = authFromAccount(objects[accountId])
	}
	if err == nil {
		log.Printf("Assuming user account: %v", suAuth)
		suApp := Authorize(app.DatabaseApp, suAuth)
		instruction := job["instruction"]
		if instruction == "check" || instruction == "run" {
			err = suApp.processRun(job)
		} else {
			err = fmt.Errorf("Invalid instruction '%v' in job: %v", instruction, job)
		}
		job[K_STATE] = "done"
	} else {
		job[K_STATE] = "failed"
	}
	if err != nil {
		job["error"] = err.Error()
	}
}

func (app *AuthorizedApp) processJob(job object) {
	// catch any database problems that occur when updating the job object
	defer func() {
		if err := recover(); err != nil {
			log.Printf("failure during completion of job '%v': %v", job[K_ID], err)
		}
	}()

	if job[K_STATE] != "pending" && job[K_STATE] != "running" {
		return
	}
	app.processJobInner(job)
	prevVersion := job[K_VERSION].(string)
	job[K_VERSION] = "done" + computeVersionString()
	tx, err := app.db.Begin()
	if err != nil {
		panic(err)
	}
	if err := app.doUpsert(tx, job, prevVersion); err != nil {
		tx.Rollback()
		panic(err)
	}
	if err := tx.Commit(); err != nil {
		panic(err)
	}
}

func (app *AuthorizedApp) Worker(no int, sourceChan chan object) {
	log.Printf("Worker %v starting", no)
	defer log.Printf("Worker %v shutting down", no)

	for job := range sourceChan {
		log.Printf("Worker %v processing job: %v", no, job)
		app.processJob(job)
	}
}

func (app *AuthorizedApp) LoadJobsWorker(doneChan chan struct{}) {
	targetChan := app.jobQueue
	for {
		select {
		case _ = <-doneChan:
			close(targetChan)
			break
		default:
			var ids []string
			objects := make(objectMap)
			// It was a nice idea only loading pending or running jobs, but we need to clean them jobs, too!
			// clauses := `natural join pr_job`
			clauses := `where type = "job"`
			if err := app.queryDB(objects, clauses, 10000, &ids); err != nil {
				log.Fatal("Error in LoadJobsWorker:", err)
			}
			log.Printf("LoadJobsWorker retrieved %v jobs from db", len(ids))
			removals := make([]string, 0, len(ids))
			referenceTime := time.Now().Unix() - 24*3600 // delete jobs that are at least a day old
			for _, id := range ids {
				job := objects[id]
				state := job[K_STATE].(string)
				version := job[K_VERSION].(string)
				// no worries about submitting a job twice; DeliverJobsWorker keeps an "already delivered" list
				// submit job regardless of state; so DeliverJobsWorker kann tidy up said list...
				targetChan <- job
				if state != "running" && state != "pending" {
					if ci := strings.IndexRune(version, '+'); ci != -1 {
						// e.g., "done+1567094170", cf. computeVersionString
						if timestamp, err := strconv.ParseInt(version[ci+1:], 10, 64); err == nil && timestamp <= referenceTime {
							removals = append(removals, id)
						}
					}
				}
			}
			if len(removals) != 0 {
				log.Printf("LoadJobsWorker going to remove %d finished jobs from database", len(removals))
				tx, err := app.db.Begin()
				if err != nil {
					panic(err)
				}
				for _, id := range removals {
					err = app.doDelete(tx, id)
					if err != nil {
						tx.Rollback()
						panic(err)
					}
				}
				if err := tx.Commit(); err != nil {
					panic(err)
				}
				log.Println("LoadJobsWorker done removing finished jobs.")
			}
		}
		time.Sleep(1 * time.Hour)
	}
}

func (app *AuthorizedApp) DeliverJobsWorker(targetChan chan object) {
	log.Printf("DeliverJobsWorker starting")
	sourceChan := app.jobQueue
	delivered := make(map[string]bool)
	for job := range sourceChan {
		id := job[K_ID].(string)
		if job[K_STATE] != "pending" && job[K_STATE] != "running" {
			delete(delivered, id)
		} else {
			if !delivered[id] {
				select {
				case targetChan <- job:
					delivered[id] = true
				default:
					// stop delivering jobs
					break
				}
			}
		}
	}
	close(targetChan)
}

func (app *DatabaseApp) BearerAuth(req *http.Request) (result *Authorization) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return
	}
	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(auth[len(prefix):], claims, func(token *jwt.Token) (interface{}, error) {
		return app.secret, nil
	})
	if err != nil || !tkn.Valid {
		log.Println(tkn, err)
		return
	}
	return &Authorization{level: claims.PrivilegeLevel, subject: claims.Subject, id: claims.AccountId}
}

func (app *DatabaseApp) BasicAuth(req *http.Request) *Authorization {
	email, passphrase, ok := req.BasicAuth()
	if !ok {
		return nil
	}
	account := app.loadAccount(email)
	authorization, err := authFromAccount(account)
	if err != nil {
		return nil
	}
	passhash, ok := account["passhash"].(string)
	if !ok {
		return nil
	}
	// The following operation is the expensive part; we try to avoid it!
	if bcrypt.CompareHashAndPassword([]byte(passhash), []byte(passphrase)) != nil {
		// TODO block the corresponding email (or at least remote party/IP address) from logging in
		// for ever increasing amounts of time (in order to prevent denial-of-service attacks)
		return nil
	}
	return authorization
}

func rootApp(app *DatabaseApp) *AuthorizedApp {
	var transformer Transformer = NullTransformer{}
	return &AuthorizedApp{app, &Authorization{id: "root", level: ROOT, subject: "root"}, app.MatViewsForLevel(ROOT), transformer}
}

type AppEndpoint struct {
	authorize func(*http.Request) *Authorization
	app       *DatabaseApp
	method    string
	minLevel  int
	server    func(*AuthorizedApp, http.ResponseWriter, *http.Request) error
}

type HasHTTPStatusCode interface {
	StatusCode() int
}

type PermissionDenied struct{ error }
type BadRequest struct{ error }
type PreconditionFailed struct{ error }

func (err PermissionDenied) StatusCode() int {
	return http.StatusForbidden
}

func (err BadRequest) StatusCode() int {
	return http.StatusBadRequest
}

func (err PreconditionFailed) StatusCode() int {
	return http.StatusPreconditionFailed
}

func (err ObjectError) StatusCode() int {
	code, _ := err.obj["code"].(int)
	return code
}

func (endpoint *AppEndpoint) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	authorization := endpoint.authorize(req)
	if authorization == nil {
		authorization = &Authorization{level: GUEST, id: "guest", subject: "guest"}
	}
	if authorization.level > endpoint.minLevel {
		http.Error(w, "Insufficient privileges", http.StatusForbidden)
		return
	}
	if req.Method != endpoint.method {
		http.Error(w, "Unsupported HTTP verb", http.StatusNotFound)
		return
	}
	authorizedApp := Authorize(endpoint.app, authorization)
	err := endpoint.server(authorizedApp, w, req)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch e := err.(type) {
		case HasHTTPStatusCode:
			statusCode = e.StatusCode()
		case PermissionDenied:
			statusCode = http.StatusForbidden
		case BadRequest:
			statusCode = http.StatusBadRequest
		}
		http.Error(w, err.Error(), statusCode)
	}
}

func (authorizedApp *AuthorizedApp) ServeLoginEndpoint(w http.ResponseWriter, req *http.Request) error {
	log.Printf("GET /api/login %v", authorizedApp.auth.subject)
	if strings.HasPrefix(req.Header.Get("Content-Type"), "application/json") {
		var kv map[string]string
		if err := json.NewDecoder(req.Body).Decode(&kv); err != nil {
			return BadRequest{err}
		}
		newpass, present := kv["newpass"]
		if !present {
			return BadRequest{errors.New("Request to change password without 'newpass'")}
		}
		objects := make(objectMap)
		if err := objects.queryByKeys(authorizedApp.db, []string{authorizedApp.auth.id}); err != nil {
			return err
		}
		account := objects[authorizedApp.auth.id]
		passhash, err := bcrypt.GenerateFromPassword([]byte(newpass), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		account["passhash"] = string(passhash)
		tx, err := authorizedApp.db.Begin()
		if err != nil {
			return err
		}
		if err := authorizedApp.doUpsert(tx, account, "*"); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	claims := &Claims{}
	claims.PrivilegeLevel = authorizedApp.auth.level
	claims.AccountId = authorizedApp.auth.id
	claims.Subject = authorizedApp.auth.subject
	claims.IssuedAt = time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(authorizedApp.secret)
	if err != nil {
		return err
	}
	w.Header().Add("content-type", "text/plain; charset=utf-8")
	w.Write([]byte(tokenString))
	return nil
}

func (app *DatabaseApp) sendObject(obj interface{}, w http.ResponseWriter) error {
	w.Header().Add("content-type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(obj)
}

func (app *DatabaseApp) insertTemplate(objects objectMap, obj object, data string) ([]byte, error) {
	wr := new(bytes.Buffer)
	idx := strings.Index(data, "##\n# ")
	suffix := ""
	if idx >= 0 {
		suffix = data[idx:]
		data = data[:idx]
	}
	wr.WriteString(data)
	if len(strings.TrimSpace(data)) != 0 && !strings.HasSuffix(data, "\n\n\n") {
		wr.WriteString("\n\n\n")
	}
	if err := app.inter.Serialize(wr, objects, obj); err != nil {
		return nil, err
	}
	wr.WriteString("\n")
	if suffix != "" {
		wr.WriteString("\n\n\n")
		wr.WriteString(suffix)
	}
	return wr.Bytes(), nil
}

func (authorizedApp *AuthorizedApp) doUpdateScratchpad(sp object, content, prevVersion string) error {
	// log.Println(content)
	sp["content"] = content
	sp[K_VERSION] = computeVersionString()
	tx, err := authorizedApp.db.Begin()
	if err != nil {
		return err
	}
	if err := authorizedApp.doUpsert(tx, sp, prevVersion); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (authorizedApp *AuthorizedApp) doInsertCreate(id, prevVersion, typ string, tags ...string) (sp object, err error) {
	objects := make(objectMap)
	if err := authorizedApp.loadFromDatabase(objects, append([]string{id}, tags...), FOLLOW|EXTRACT); err != nil {
		return nil, err
	}
	sp = objects[id]
	owner, _ := sp["$owner"].(string) // owner check will be done by doUpsert
	obj := object{
		K_TYPE:       typ,
		K_ID:         uuid.Must(uuid.NewRandom()).String(),
		"date":       strconv.FormatInt(time.Now().Unix(), 10),
		"paraph":     objects[owner]["paraph"],
		"visibility": "editor",
		"_creating":  true,
	}
	if len(tags) > 0 {
		ts := make([]interface{}, len(tags))
		for i, t := range tags {
			ts[i] = interface{}(t)
		}
		obj["$tags"] = interface{}(ts)
	}
	b, err := authorizedApp.insertTemplate(objects, obj, sp["content"].(string))
	if err != nil {
		return nil, err
	}
	if err := authorizedApp.doUpdateScratchpad(sp, string(b), prevVersion); err != nil {
		return nil, err
	}
	return
}

func (authorizedApp *AuthorizedApp) doInsertLoad(id, prevVersion, target string) (sp object, err error) {
	objects := make(objectMap)
	if err := authorizedApp.loadFromDatabase(objects, []string{id, target}, FOLLOW|EXTRACT); err != nil {
		return nil, err
	}
	sp = objects[id]
	b, err := authorizedApp.insertTemplate(objects, objects[target], sp["content"].(string))
	if err != nil {
		return nil, err
	}
	if err := authorizedApp.doUpdateScratchpad(sp, string(b), prevVersion); err != nil {
		return nil, err
	}
	return
}

func (authorizedApp *AuthorizedApp) doRun(id, prevVersion, instruction string) (job object, err error) {
	objects := make(objectMap)
	// make sure the scratchpad exists, belongs to us, and has the correct version
	if err := authorizedApp.loadFromDatabase(objects, []string{id}, NOFOLLOW|EXTRACT); err != nil {
		return nil, err
	}
	if authorizedApp.auth.level > ADMIN && objects[id]["$owner"] != authorizedApp.auth.id {
		return nil, PermissionDenied{fmt.Errorf("Current user '%v' not authorized to run check job on scratchpad '%v'", authorizedApp.auth.id, id)}
	}
	version, _ := objects[id][K_VERSION].(string)
	if version != prevVersion {
		return nil, PreconditionFailed{fmt.Errorf("Version did not match: '%v' != '%v'", prevVersion, version)}
	}
	job = object{
		K_TYPE:        "job",
		K_ID:          uuid.Must(uuid.NewRandom()).String(),
		K_VERSION:     computeVersionString(),
		K_STATE:       "pending",
		"instruction": instruction,
		"error":       "",
		"$target":     id,
		"tVersion":    version,
		"$owner":      authorizedApp.auth.id,
	}
	tx, err := authorizedApp.db.Begin()
	if err != nil {
		return nil, err
	}
	if err := authorizedApp.doUpsert(tx, job, "ENOENT"); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	authorizedApp.jobQueue <- job
	return
}

func (authorizedApp *AuthorizedApp) ServeScratchpadEndpoint(w http.ResponseWriter, req *http.Request) error {
	id := req.URL.Path
	prevVersion := req.Header.Get("if-match")
	if prevVersion == "" {
		return BadRequest{errors.New("Missing if-match header")}
	}
	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return err
	}
	var result object
	instruction := strings.Split(string(b), " ")
	if len(instruction) >= 2 && instruction[0] == "create" {
		result, err = authorizedApp.doInsertCreate(id, prevVersion, instruction[1], instruction[2:]...)
	} else if len(instruction) == 2 && instruction[0] == "load" {
		result, err = authorizedApp.doInsertLoad(id, prevVersion, instruction[1])
	} else if len(instruction) == 1 && instruction[0] == "check" {
		result, err = authorizedApp.doRun(id, prevVersion, "check")
	} else if len(instruction) == 1 && instruction[0] == "run" {
		result, err = authorizedApp.doRun(id, prevVersion, "run")
	} else {
		err = BadRequest{fmt.Errorf("Malformed instruction: %v", string(b))}
	}
	if err != nil {
		return err
	}
	return authorizedApp.sendObject(result, w)
}

func (authorizedApp *AuthorizedApp) ServeUpsertEndpoint(w http.ResponseWriter, req *http.Request) error {
	app := authorizedApp
	var obj object
	prevVersion := req.Header.Get("if-match")
	if prevVersion == "" {
		return BadRequest{errors.New("Missing if-match header")}
	}
	dec := json.NewDecoder(req.Body)
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return err
	}
	tx, err := app.db.Begin()
	if err != nil {
		return err
	}
	// the following statement could be adapted to a loop for upserting multiple objects within this tx
	if err := app.doUpsert(tx, obj, prevVersion); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	w.Header().Add("content-type", "text/plain")
	w.Write([]byte(obj[K_VERSION].(string)))
	return nil
}

func (authorizedApp *AuthorizedApp) ServeViewEndpoint(w http.ResponseWriter, req *http.Request) error {
	var keys []string
	if err := json.NewDecoder(req.Body).Decode(&keys); err != nil {
		return err
	}
	log.Printf("POST /api/view %v %v", authorizedApp.auth.id, keys)
	result, err := authorizedApp.Get(keys...)
	if err != nil {
		return err
	}
	return authorizedApp.sendObject(result, w)
}

func (authorizedApp *AuthorizedApp) ServeDumpEndpoint(w http.ResponseWriter, req *http.Request) error {
	sqlStmt := `select max(rowid) from objects`
	log.Println(sqlStmt)
	rows, err := authorizedApp.db.Query(sqlStmt)
	if err != nil {
		return err
	}
	maxRowid := 0
	for rows.Next() {
		if err := rows.Scan(&maxRowid); err != nil {
			return err
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}

	w.Header().Add("content-type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)

	objects := make(objectMap)
	limit := 100
	rowid := 0
	keys := make([]string, 0, limit)
	for rowid <= maxRowid {
		keys = keys[:0]
		if err := objects.queryDB(authorizedApp.db, `where rowid >= ? and rowid < ? order by rowid`, limit, &keys, rowid, rowid+limit); err != nil {
			return err
		}
		for _, key := range keys {
			if err := enc.Encode(objects[key]); err != nil {
				return err
			}
		}
		rowid += limit
	}
	return nil
}

func (app *AuthorizedApp) loadFromReader(f io.Reader, num *int) error {
	dec := json.NewDecoder(f)
	dec.UseNumber()
	tx, err := app.db.Begin()
	if err != nil {
		return err
	}
	for true {
		var obj object
		err := dec.Decode(&obj)
		if err == io.EOF {
			break // we need to have a return statement at the end anyway...
		} else if err != nil {
			return err
		}
		if obj["__op__"] == "DELETE" {
			err = app.doDelete(tx, obj[K_ID].(string))
		} else {
			err = app.doUpsert(tx, obj, "*")
		}
		if err != nil {
			tx.Rollback()
			log.Println(obj)
			return err
		}
		*num += 1
		if *num%100 == 0 {
			if err := tx.Commit(); err != nil {
				return err
			}
			tx, err = app.db.Begin()
			if err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	app.InvalidateMatViews()
	return nil
}

func (authorizedApp *AuthorizedApp) ServeRestoreEndpoint(w http.ResponseWriter, req *http.Request) error {
	// 2fa idea: only admin can initiate restore, but the data must reside on the local file system
	// in return, restore is performed with ROOT privileges
	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return err
	}
	filepath := string(b)
	f, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer f.Close()
	num := 0
	if err := rootApp(authorizedApp.DatabaseApp).loadFromReader(f, &num); err != nil {
		return err
	}
	w.Header().Add("content-type", "text/plain")
	w.Write([]byte(fmt.Sprintf("Restored %d objects", num)))
	return nil
}

func main() {
	log.SetFlags(log.Flags() | log.Lmicroseconds)
	var port = flag.Int("port", 8282, "port to bind to")
	var revprox = flag.Bool("revprox", false, "whether to act as reverse proxy for node dev")
	flag.Parse()

	// no error handling in the following statements because of controlled environment
	devServerUrl, _ := url.Parse("http://localhost:8100/")
	productionPath, _ := filepath.Abs("../frontend/www")
	databasePath, _ := filepath.Abs("../data/database3.db")
	secretPath, _ := filepath.Abs("./secret")
	staticPath, _ := filepath.Abs("../static")
	imgPath, _ := filepath.Abs("../img")
	templatePath, _ := filepath.Abs("./templates")

	secret, err := ioutil.ReadFile(secretPath)
	if err != nil {
		log.Fatal(err)
	}
	module := CompositeModule{
		MainModule{}, ModuleDate{}, ModuleTags{}, ModuleEmail{},
		ModuleFriendlyId{}, ModuleOwner{}, ModuleJobs{},
	}
	app, err := NewDatabaseApp(databasePath, module, NewInter(templatePath), secret, imgPath)
	if err != nil {
		log.Fatal(err)
	}
	defer app.Close()

	doneChan := make(chan struct{})
	intermediate := make(chan object, 5)
	rapp := rootApp(app)
	for i := 0; i < 5; i++ {
		go rapp.Worker(i, intermediate)
	}
	go rapp.DeliverJobsWorker(intermediate)
	go rapp.LoadJobsWorker(doneChan)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticPath))))
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir(imgPath))))
	apiMux := http.NewServeMux()
	apiMux.Handle("/login", &AppEndpoint{app.BasicAuth, app, "POST", PREMIUM, (*AuthorizedApp).ServeLoginEndpoint})
	apiMux.Handle("/view", &AppEndpoint{app.BearerAuth, app, "POST", GUEST, (*AuthorizedApp).ServeViewEndpoint})
	apiMux.Handle("/upsert", &AppEndpoint{app.BearerAuth, app, "POST", EDITOR, (*AuthorizedApp).ServeUpsertEndpoint})
	apiMux.Handle("/scratchpad/", http.StripPrefix("/scratchpad/", &AppEndpoint{app.BearerAuth, app, "PATCH", EDITOR, (*AuthorizedApp).ServeScratchpadEndpoint}))
	apiMux.Handle("/dump", &AppEndpoint{app.BearerAuth, app, "POST", ADMIN, (*AuthorizedApp).ServeDumpEndpoint})
	apiMux.Handle("/restore", &AppEndpoint{app.BearerAuth, app, "POST", ADMIN, (*AuthorizedApp).ServeRestoreEndpoint})
	http.Handle("/api/", http.StripPrefix("/api", apiMux))
	if *revprox {
		log.Printf("Activating reverse proxy for %v", devServerUrl)
		http.Handle("/", httputil.NewSingleHostReverseProxy(devServerUrl))
	} else {
		http.Handle("/", http.FileServer(http.Dir(productionPath)))
	}
	log.Printf("Listening on port %v", *port)
	panic(http.ListenAndServe(fmt.Sprintf(":%v", *port), nil))
}
