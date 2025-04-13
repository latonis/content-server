package contentserver

import (
	"html/template"
	"slices"
	"sort"
	"strings"
	"time"
)

type MetaDate struct {
	Time time.Time `yaml:"date"`
}

type PostMeta struct {
	Title       string   `yaml:"title"`
	Date        MetaDate `yaml:"date"`
	Categories  []string `yaml:"categories"`
	Description string   `yaml:"description"`
}

func (t *MetaDate) UnmarshalYAML(unmarshal func(interface{}) error) error {

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

type Post struct {
	Slug string
	Meta PostMeta
	Body template.HTML
}

func GetPostsByDate(posts map[string]Post) []Post {
	postsByDate := make([]Post, 0)
	for _, post := range posts {
		postsByDate = append(postsByDate, post)
	}

	slices.SortFunc(postsByDate, func(i, j Post) int {
		if i.Meta.Date.Time.After(j.Meta.Date.Time) {
			return -1
		} else if i.Meta.Date.Time.Before(j.Meta.Date.Time) {
			return 1
		}
		return 0
	})

	return postsByDate
}

func GetCategories(posts map[string]Post) []string {
	categories := make([]string, 0)

	for _, post := range posts {
		for _, category := range post.Meta.Categories {
			lower_category := strings.ToLower(category)
			if !slices.Contains(categories, lower_category) {
				categories = append(categories, lower_category)
			}
		}
	}

	return categories
}

func GetPostsByCategory(posts map[string]Post) map[string][]Post {
	postsByCategory := make(map[string][]Post)

	for _, post := range posts {
		for _, category := range post.Meta.Categories {
			lower_category := strings.ToLower(category)
			postsByCategory[lower_category] = append(postsByCategory[lower_category], post)
		}
	}

	for category := range postsByCategory {
		sort.SliceStable(postsByCategory[category], func(i, j int) bool {
			return postsByCategory[category][i].Meta.Date.Time.Before(postsByCategory[category][j].Meta.Date.Time)
		})
	}

	return postsByCategory
}
