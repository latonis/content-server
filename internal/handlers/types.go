package contentserver

import (
	"html/template"
	"strings"
	"time"
)

type Post struct {
	Slug string
	Meta PostMeta
	Body template.HTML
}

type MetaDate struct {
	Time time.Time `yaml:"date"`
}

func (t *MetaDate) UnmarshalYAML(unmarshal func(any) error) error {

	var buf string
	err := unmarshal(&buf)
	if err != nil {
		return nil
	}

	tt, err := time.Parse("2006-01-02", strings.TrimSpace(buf))
	if err != nil {
		return err
	}
	t.Time = tt
	return nil
}

type PostMeta struct {
	Title       string   `yaml:"title"`
	Date        MetaDate `yaml:"date"`
	Categories  []string `yaml:"categories"`
	Description string   `yaml:"description"`
}
