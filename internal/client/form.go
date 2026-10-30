package client

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Field is a single name/value pair of a form submission.
type Field struct {
	Name  string
	Value string
}

// Form is an ordered list of form fields, as a browser would submit them.
type Form struct {
	Fields []Field
}

// ParseForm serializes the form with the given name attribute found in doc,
// like a browser would submit it without any JavaScript running: disabled
// controls and unchecked checkboxes/radios are skipped, a select submits its
// selected (or first) option. When formName is empty, every control in the
// document is collected regardless of the enclosing form.
func ParseForm(doc, formName string) *Form {
	f := &Form{}
	z := html.NewTokenizer(strings.NewReader(doc))

	inForm := formName == ""
	var sel *selectState

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return f
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			attrs := attrMap(tok.Attr)
			switch tok.Data {
			case "form":
				if formName != "" {
					inForm = attrs["name"] == formName
				}
			case "input":
				if !inForm {
					continue
				}
				addInput(f, attrs)
			case "select":
				if !inForm {
					continue
				}
				_, disabled := attrs["disabled"]
				sel = &selectState{name: attrs["name"], disabled: disabled}
			case "option":
				if sel == nil {
					continue
				}
				v, ok := attrs["value"]
				if !ok {
					v = ""
				}
				if !sel.hasFirst {
					sel.first, sel.hasFirst = v, true
				}
				if _, ok := attrs["selected"]; ok && !sel.hasSelected {
					sel.selected, sel.hasSelected = v, true
				}
			}
		case html.EndTagToken:
			tok := z.Token()
			switch tok.Data {
			case "form":
				if formName != "" {
					inForm = false
				}
			case "select":
				if sel != nil && sel.name != "" && !sel.disabled {
					v := sel.first
					if sel.hasSelected {
						v = sel.selected
					}
					f.Fields = append(f.Fields, Field{Name: sel.name, Value: v})
				}
				sel = nil
			}
		}
	}
}

type selectState struct {
	name        string
	disabled    bool
	first       string
	hasFirst    bool
	selected    string
	hasSelected bool
}

func attrMap(attrs []html.Attribute) map[string]string {
	m := make(map[string]string, len(attrs))
	for _, a := range attrs {
		m[a.Key] = a.Val
	}
	return m
}

func addInput(f *Form, attrs map[string]string) {
	name := attrs["name"]
	if name == "" {
		return
	}
	if _, ok := attrs["disabled"]; ok {
		return
	}
	typ := strings.ToLower(attrs["type"])
	switch typ {
	case "button", "submit", "reset", "file", "image":
		return
	case "checkbox", "radio":
		if _, ok := attrs["checked"]; !ok {
			return
		}
		v, ok := attrs["value"]
		if !ok {
			v = "on"
		}
		f.Fields = append(f.Fields, Field{Name: name, Value: v})
	default:
		f.Fields = append(f.Fields, Field{Name: name, Value: attrs["value"]})
	}
}

// Get returns the value of the first field with the given name.
func (f *Form) Get(name string) (string, bool) {
	for _, fl := range f.Fields {
		if fl.Name == name {
			return fl.Value, true
		}
	}
	return "", false
}

// Set replaces the value of every field with the given name, or appends a new
// field when none exists.
func (f *Form) Set(name, value string) {
	found := false
	for i := range f.Fields {
		if f.Fields[i].Name == name {
			f.Fields[i].Value = value
			found = true
		}
	}
	if !found {
		f.Fields = append(f.Fields, Field{Name: name, Value: value})
	}
}

// SetIfPresent replaces the value of an existing field and reports whether
// the field exists.
func (f *Form) SetIfPresent(name, value string) bool {
	found := false
	for i := range f.Fields {
		if f.Fields[i].Name == name {
			f.Fields[i].Value = value
			found = true
		}
	}
	return found
}

// Add appends a field, even when a field with the same name exists.
func (f *Form) Add(name, value string) {
	f.Fields = append(f.Fields, Field{Name: name, Value: value})
}

// Del removes every field with the given name.
func (f *Form) Del(name string) {
	out := f.Fields[:0]
	for _, fl := range f.Fields {
		if fl.Name != name {
			out = append(out, fl)
		}
	}
	f.Fields = out
}

// Encode encodes the form as application/x-www-form-urlencoded, keeping the
// field order like a browser does.
func (f *Form) Encode() string {
	var b strings.Builder
	for i, fl := range f.Fields {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(fl.Name))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(fl.Value))
	}
	return b.String()
}
