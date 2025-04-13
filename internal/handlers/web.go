package contentserver

import (
	"slices"
	"sort"
	"strings"
)

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
