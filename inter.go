// copyright Matthias Büchse, 2019
package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode"
)

type Inter interface {
	Serialize(wr io.Writer, objects objectMap, obj object) error
}

func formatDate(layout string, date interface{}) string {
	var dateStr string
	switch v := date.(type) {
	case json.Number:
		dateStr = string(v)
	case string:
		dateStr = v
	default:
		dateStr = ""
	}
	i64, err := strconv.ParseInt(dateStr, 10, 64)
	if err != nil {
		log.Fatal(err)
	}
	return time.Unix(i64, 0).Format(layout)
}

func friendly(objects objectMap, key string) interface{} {
	return objects[key]["friendlyId"]
}

func joinStrings(delim string, args []interface{}) string {
	sargs := make([]string, len(args))
	for i, arg := range args {
		sargs[i] = arg.(string)
	}
	return strings.Join(sargs, delim)
}

type myTemplate struct {
	tmpl *template.Template
}

func NewInter(templatePath string) Inter {
	result := myTemplate{template.New("blubb")}
	t := result.tmpl
	t.Funcs(map[string]interface{}{"formatDate": formatDate, "friendly": friendly, "joinStrings": joinStrings})
	template.Must(t.ParseGlob(templatePath + "/*"))
	return result
}

func (template myTemplate) Serialize(wr io.Writer, objects objectMap, obj object) error {
	// obviously not re-entrant
	restore := func() { delete(objects, "_current") }
	defer restore()
	objects["_current"] = obj
	return template.tmpl.ExecuteTemplate(wr, obj[K_TYPE].(string), objects)
}

const (
	SKIP  = -1
	INFO  = 0
	HINT  = 1
	ERROR = 2
	MAX   = 2
)

type remark struct {
	line     int
	text     string
	severity int
	skip     int
}

// for sorting
type RemarkSlice []*remark

func (p RemarkSlice) Len() int           { return len(p) }
func (p RemarkSlice) Less(i, j int) bool { return p[i].line < p[j].line }
func (p RemarkSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func (r remark) Format() string {
	if r.severity == SKIP {
		return ""
	} else if r.severity == ERROR {
		return fmt.Sprintf("#! >>>>>>>>>>>>>>>>>>>> %v <<<<<<<<<<<<<<<<<<<<\n", r.text)
	} else if r.severity == HINT {
		return fmt.Sprintf("#: >>>>>>>> %v <<<<<<<<\n", r.text)
	} else {
		return fmt.Sprintf("#: %v\n", r.text)
	}
}

type Remarks struct {
	histo       [MAX + 1]int
	severity    int
	descriptors []*remark
}

func New() *Remarks {
	return &Remarks{[MAX + 1]int{}, 0, make([]*remark, 0)}
}

func (rs *Remarks) add(r *remark) {
	rs.descriptors = append(rs.descriptors, r)
	if r.severity > rs.severity {
		rs.severity = r.severity
	}
	if r.severity >= 0 && r.severity <= MAX {
		rs.histo[r.severity]++
	}
}

func (rs *Remarks) AddError(line int, text string, args ...interface{}) {
	rs.add(&remark{line, fmt.Sprintf(text, args...), ERROR, 0})
}

func (rs *Remarks) AddHint(line int, text string, args ...interface{}) {
	rs.add(&remark{line, fmt.Sprintf(text, args...), HINT, 0})
}

func (rs *Remarks) AddInfo(line int, text string, args ...interface{}) {
	rs.add(&remark{line, fmt.Sprintf(text, args...), INFO, 0})
}

func (rs *Remarks) AddRemover(line int) {
	r := &remark{line: line, severity: SKIP, skip: 1}
	rs.descriptors = append(rs.descriptors, r)
}

func (rs *Remarks) Embed(contentLines []string) string {
	content := ""
	cl := 0
	sort.Sort(RemarkSlice(rs.descriptors))
	for _, ed := range rs.descriptors {
		if ed.line-cl >= 0 {
			content += strings.Join(contentLines[cl:ed.line], "\n")
			if ed.line-cl > 0 {
				content += "\n"
			}
			cl = ed.line + ed.skip
		}
		content += ed.Format()
	}
	content += strings.Join(contentLines[cl:], "\n")
	return content
}

func (rs *Remarks) Severity() int {
	return rs.severity
}

func (rs *Remarks) Histo(severity int) int {
	if severity >= 0 && severity <= MAX {
		return rs.histo[severity]
	}
	return 0
}

type HeaderTransfer interface {
	collectFriendly(friendly *[]string)
	transfer(obj object, lookup map[string]object)
}

type Header struct {
	line     int
	transfer HeaderTransfer
}

type objectDescriptor struct {
	start   int
	initial []string
	header  map[string]Header
	body    []string
}

type HeaderParser interface {
	parse(value string) (HeaderTransfer, error)
}

type verbatimString struct {
	targetKey string
	values    []string
	noTrim    bool // default: trim spaces (so much for "verbatim")
}

type verbatimList struct {
	targetKey string
}

type referenceList struct {
	targetKey string
}

type dateField struct {
	targetKey string
}

type snippetField struct{}

type verbatimTransfer struct {
	targetKey string
	value     interface{}
}

type referenceTransfer struct {
	targetKey string
	friendly  []string
}

type snippetTransfer object

func (vt *verbatimTransfer) collectFriendly(friendly *[]string) {
}

func (vt *verbatimTransfer) transfer(obj object, lookup map[string]object) {
	if vt.value == nil {
		delete(obj, vt.targetKey)
	} else {
		obj[vt.targetKey] = vt.value
	}
}

func (vs verbatimString) parse(value string) (HeaderTransfer, error) {
	if !vs.noTrim {
		value = strings.TrimSpace(value)
	}
	var ivalue interface{} = value
	if vs.values != nil {
		i := -1
		for j, v := range vs.values {
			if value == v {
				i = j
				break
			}
		}
		if i == -1 {
			return nil, fmt.Errorf("field value needs to be one of: %v", vs.values)
		}
		if value == "" {
			// FAT DOG: if we have a fixed set of possible values, "" means <remove field>
			ivalue = nil
		}
	}
	return &verbatimTransfer{vs.targetKey, ivalue}, nil
}

func parseList(value string) []string {
	// CAUTION: separator is COMMA followed by SPACE, because (e.g.) URLs may contain commas (but not spaces)
	values := strings.Split(value, ", ")
	for i, v := range values {
		values[i] = strings.TrimSpace(v)
	}
	if len(values) >= 1 && values[len(values)-1] == "" {
		// handle empty list as well as trailing comma
		values = values[:len(values)-1]
	}
	return values
}

func (vl verbatimList) parse(value string) (HeaderTransfer, error) {
	return &verbatimTransfer{vl.targetKey, parseList(value)}, nil
}

func (rt *referenceTransfer) collectFriendly(friendly *[]string) {
	*friendly = append(*friendly, rt.friendly...)
}

func (rt *referenceTransfer) transfer(obj object, lookup map[string]object) {
	fIds := make([]interface{}, len(rt.friendly))
	for i, f := range rt.friendly {
		fIds[i] = lookup[f][K_ID]
	}
	obj[rt.targetKey] = interface{}(fIds)
}

func (rl referenceList) parse(value string) (HeaderTransfer, error) {
	return &referenceTransfer{rl.targetKey, parseList(value)}, nil
}

func (df dateField) parse(value string) (HeaderTransfer, error) {
	t, err := time.Parse("2006-01-02 15:04:05 -0700", strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	return &verbatimTransfer{df.targetKey, strconv.FormatInt(t.Unix(), 10)}, nil
}

func findQuote(s, start, end string) string {
	i1 := strings.Index(s, start)
	if i1 == -1 {
		return ""
	}
	i2 := strings.Index(s[i1+len(start):], end)
	if i2 == -1 {
		return ""
	}
	return s[i1+len(start) : i1+len(start)+i2]
}

func resolveRedirects(url *string) error {
	req, err := http.NewRequest("HEAD", *url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	*url = resp.Request.URL.String()
	return nil
}

func (sf snippetField) parse(value string) (HeaderTransfer, error) {
	st := make(snippetTransfer)
	if strings.Index(value, `.statista.com/`) != -1 {
		if sourceUrl := findQuote(value, `<a href="`, `"`); sourceUrl != "" {
			st["sourceUrl"] = sourceUrl
		} else {
			return st, errors.New(`could not find source url; expected «<a href="..."»`)
		}
		if imageUrl := findQuote(value, `<img src="`, `"`); imageUrl != "" {
			st["imageUrl"] = imageUrl
		} else {
			return st, errors.New(`could not find image url; expected «<img src="..."»`)
		}
		if altText := findQuote(value, ` alt="`, `"`); altText != "" {
			st["name"] = altText
		} else {
			return st, errors.New(`could not find title; expected «alt="..."»`)
		}
		maxWidth := strings.TrimSpace(findQuote(value, `max-width:`, `px;`))
		if maxWidth == "1000" {
			st["kind"] = "statista/statistik"
		} else if maxWidth == "960" {
			st["kind"] = "statista/infografik"
		} else {
			return st, errors.New(`could not determine kind; expected «max-width:...px;»`)
		}
	} else if strings.Index(value, `.amazon.de/`) != -1 {
		if purchaseUrl := findQuote(value, ` href="`, `"`); purchaseUrl != "" {
			st["buyUrl"] = purchaseUrl
		} else {
			return st, errors.New(`could not find purchase url; expected « href="..."»`)
		}
		if imageUrl := findQuote(value, ` src="`, `"`); imageUrl != "" {
			if strings.HasPrefix(imageUrl, "//") {
				imageUrl = "http:" + imageUrl
			}
			if err := resolveRedirects(&imageUrl); err != nil {
				return st, err
			}
			st["imageUrl"] = imageUrl
		} else {
			return st, errors.New(`could not find image url; expected « src="..."»`)
		}
	} else {
		return st, errors.New(`snippet not recognized; expected to find «.statista.com/» or «.amazon.de/»`)
	}
	return st, nil
}

func (st snippetTransfer) collectFriendly(friendly *[]string) {
}

func (st snippetTransfer) transfer(obj object, lookup map[string]object) {
	for k, v := range st {
		obj[k] = v
	}
}

func CollectFriendly(ods ...objectDescriptor) []string {
	friendly := make([]string, 0)
	for _, od := range ods {
		for _, h := range od.header {
			h.transfer.collectFriendly(&friendly)
		}
	}
	return friendly
}

func CollectMissing(ht HeaderTransfer, lookup map[string]object) []string {
	friendly := make([]string, 0)
	ht.collectFriendly(&friendly)
	missing := make([]string, 0)
	for _, f := range friendly {
		if _, present := lookup[f]; !present {
			missing = append(missing, f)
		}
	}
	return missing
}

var headerParsers = map[string]HeaderParser{
	"friendly-id":   verbatimString{targetKey: "friendlyId"},
	"date":          dateField{"date"},
	"title":         verbatimString{targetKey: "name"},
	"tags":          referenceList{"$tags"},
	"source-urls":   verbatimList{"sourceUrls"},
	"paraph":        verbatimString{targetKey: "paraph"},
	"visibility":    verbatimString{targetKey: "visibility", values: []string{"", "editor"}},
	"dateline":      verbatimString{targetKey: "dateline"},
	"image-url":     verbatimString{targetKey: "imageUrl"},
	"image-credits": verbatimString{targetKey: "imageCredits"},
	"image-source":  verbatimString{targetKey: "imageSource"},
	"image-text":    verbatimString{targetKey: "imageText"},
	"components":    referenceList{"$components"},
	"speaker":       verbatimString{targetKey: "speaker"},
	"position":      verbatimString{targetKey: "position"},
	"sources":       verbatimString{targetKey: "sources"},
	"snippet":       snippetField{},
	"kind":          verbatimString{targetKey: "kind", values: []string{"statista/statistik", "statista/infografik"}},
	"source-url":    verbatimString{targetKey: "sourceUrl"},
	"origin":        verbatimString{targetKey: "origin"},
	"origin-url":    verbatimString{targetKey: "originUrl"},
	"authors":       verbatimString{targetKey: "authors"},
	"publisher":     verbatimString{targetKey: "publisher"},
	"purchase-url":  verbatimString{targetKey: "purchaseUrl"},
}

func computeHeaderLookup(data map[string]string) map[string]map[string]bool {
	result := make(map[string]map[string]bool, len(data))
	for key, fieldstr := range data {
		fields := strings.Split(strings.ToLower(fieldstr), " ")
		set := make(map[string]bool, len(fields))
		for _, f := range fields {
			set[strings.TrimSpace(f)] = true
		}
		result[key] = set
	}
	return result
}

var validHeaders = computeHeaderLookup(map[string]string{
	"COMPONENT": "Friendly-Id Date Title Tags Source-Urls",
	"EVENT":     "Friendly-Id Date Paraph Visibility Tags Dateline Title Image-Url Image-Credits Image-Source Image-Text Components",
	"STATEMENT": "Friendly-Id Date Paraph Visibility Tags Speaker Position Image-Url Image-Credits Image-Source Sources Source-Urls",
	"STATISTIC": "Friendly-Id Date Paraph Visibility Tags Snippet Kind Title Source-Url Image-Url Origin Origin-Url",
	"BOOK":      "Friendly-Id Date Paraph Visibility Tags Authors Title Publisher Snippet Image-Url Purchase-Url",
})

var hasBody = map[string]bool{
	"COMPONENT": true,
	"STATEMENT": true,
}

func parseInter(contentLines []string, remarks *Remarks) (ods []objectDescriptor) {
	ods = make([]objectDescriptor, 0)
	if len(contentLines) == 0 {
		return
	}
	contentLines = append(append(contentLines, ""), "") // sentinel for storing the final object
	cod := objectDescriptor{start: -1}
	blanks := 0
	fieldStart := 0
	headerKey := ""
	headerValue := ""

	finishField := func() {
		hk := headerKey
		if hk == "" {
			return
		}
		headerKey = ""
		if !validHeaders[cod.initial[0]][hk] {
			remarks.AddError(fieldStart, "invalid header field: %v", hk)
			return
		}
		parser, present := headerParsers[hk]
		if !present {
			remarks.AddError(fieldStart, "unknown header field: %v", hk)
		}
		ht, err := parser.parse(headerValue)
		if err != nil {
			remarks.AddError(fieldStart, "error parsing field: %v", err.Error())
			return
		}
		cod.header[hk] = Header{fieldStart, ht}
	}

	for i, l := range contentLines {
		// no trimming yet, for whitespace makes a difference (continuation of header field)
		if l == "" {
			blanks += 1
			if cod.start == -1 {
				continue // !!!
			}
			if headerKey != "" {
				finishField()
			}
			if blanks == 2 || !hasBody[cod.initial[0]] {
				ods = append(ods, cod)
				cod = objectDescriptor{start: -1}
				continue // !!!
			}
			if cod.body == nil {
				cod.body = make([]string, 0)
			} else {
				cod.body = append(cod.body, "")
			}
			continue // !!!
		}
		// blanks only counts consecutive EMPTY lines; a line containing only a comment is ignored, but not counted!
		blanks = 0
		// body takes preference before comments (no special handling of # in body)
		if cod.body != nil {
			cod.body = append(cod.body, l)
			continue // !!!
		}
		// a comment is either prefixed by "#"" at the beginning of the line or by " #" otherwise
		ci := 0
		if !strings.HasPrefix(l, "#") {
			ci = strings.Index(l, " #")
		}
		if ci != -1 {
			if ci == 0 {
				// disallow header continuation
				finishField()
				// remove remark
				if strings.HasPrefix(l, "#!") || strings.HasPrefix(l, "#:") {
					remarks.AddRemover(i)
				}
			}
			l = l[:ci]
		}
		if l == "" {
			continue // !!!
		}
		if cod.start == -1 {
			cod.initial = strings.SplitN(l, " ", 2)
			for j, ini := range cod.initial {
				cod.initial[j] = strings.TrimSpace(ini)
			}
			if len(cod.initial) != 2 || strings.IndexByte(cod.initial[1], ' ') != -1 {
				remarks.AddError(i, "expected initial line of the form 'TYPE id'")
			} else {
				if _, present := validHeaders[cod.initial[0]]; present {
					cod.start = i
					cod.header = make(map[string]Header)
				} else {
					remarks.AddError(i, "unknown type: %v", cod.initial[0])
				}
			}
			continue // !!!
		}
		if headerKey != "" && unicode.IsSpace(rune(l[0])) {
			// continuation of previous header; do NOT trim trailing space! (see below)
			headerValue += " " + strings.TrimLeftFunc(l, unicode.IsSpace)
			continue // !!!
		}
		hs := strings.SplitN(l, ":", 2)
		if len(hs) != 2 {
			remarks.AddError(i, "expected header line of the form 'Key: Value'")
		} else {
			finishField()
			fieldStart = i
			headerKey = strings.ToLower(hs[0])
			if _, present := cod.header[headerKey]; present {
				remarks.AddError(i, "redeclared header field: %v", headerKey)
			}
			// do NOT trim trailing space for it may carry semantics (such as trailing COMMA SPACE)
			headerValue = strings.TrimLeftFunc(hs[1], unicode.IsSpace)
		}
	}
	return
}

func computeFriendly(title string) string {
	fields := strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) {
			return unicode.ToLower(r)
		} else {
			return ' '
		}
	}, title))
	l := 0
	i := 0
	for l < 33 && i < len(fields) {
		l += len(fields[i])
		l += 1
		i++
	}
	if l < 33 {
		return ""
	}
	return strings.Join(fields[:i], "-")
}

func applyToObjects(db *sql.DB, ods []objectDescriptor, objects objectMap, remarks *Remarks, initialVersion string) error {
	friendlyMap := make(map[string]object)
	// collect references and load them from the database
	friendly := CollectFriendly(ods...)
	if err := objects.queryByFriendly(db, friendly, nil); err != nil {
		return err
	}
	for _, obj := range objects {
		if friendly, ok := obj["friendlyId"].(string); ok {
			friendlyMap[friendly] = obj
		}
	}
	// load objects from database (those that exist anyway)
	keys := make([]string, len(ods))
	for i, od := range ods {
		keys[i] = od.initial[1]
	}
	if err := objects.queryByKeys(db, keys); err != nil {
		return err
	}
	// transfer fields from objectDescriptors into objects
	for odi, od := range ods {
		obj, present := objects[od.initial[1]]
		if !present {
			obj = object{K_TYPE: strings.ToLower(od.initial[0]), K_ID: od.initial[1], K_VERSION: initialVersion}
			objects[od.initial[1]] = obj
		}
		for _, h := range od.header {
			missing := CollectMissing(h.transfer, friendlyMap)
			if len(missing) == 0 {
				h.transfer.transfer(obj, friendlyMap)
			} else {
				for _, m := range missing {
					remarks.AddError(h.line, "NOT FOUND: %v", m)
				}
			}
		}
		// handle body
		if od.body == nil {
			delete(obj, "content")
		} else {
			obj["content"] = strings.Join(od.body, "\n")
		}
		// handle non-extant components :(
		if _, present := obj["$components"]; !present && obj[K_TYPE] == "event" {
			i := odi
			for ; i > 0 && ods[i-1].initial[0] == "COMPONENT"; i-- {
			}
			if i < odi {
				cs := make([]interface{}, odi-i)
				for j := i; j < odi; j++ {
					cs[j-i] = ods[j].initial[1]
				}
				obj["$components"] = interface{}(cs)
			}
		}
		// handle non-extant friendlyId
		if friendly, present := obj["friendlyId"]; present {
			keys := make([]string, 0)
			if err := objects.queryByFriendly(db, []string{friendly.(string)}, &keys); err != nil {
				return err
			}
			if len(keys) != 0 && keys[0] != od.initial[1] {
				remarks.AddError(od.start, "Friendly-Id already taken")
			}
		} else {
			friendly := ""
			if title, ok := obj["content"].(string); ok {
				friendly = computeFriendly(title)
			}
			if title, ok := obj["name"].(string); friendly == "" && ok {
				friendly = computeFriendly(title)
			}
			if friendly != "" {
				friendlyBase := friendly
				for fi := 0; ; fi++ {
					// I'm afraid we have to check for uniqueness
					if fi != 0 {
						friendly = friendlyBase + "-" + strconv.Itoa(fi)
					}
					keys := make([]string, 0)
					if err := objects.queryByFriendly(db, []string{friendly}, &keys); err != nil {
						return err
					}
					if len(keys) == 0 {
						break
					}
				}
				obj["friendlyId"] = friendly
				friendlyMap[friendly] = obj
			} else {
				remarks.AddError(od.start, "could not compute Friendly-Id; check title or text body")
			}
		}
	}
	return nil
}
