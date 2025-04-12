package contentserver

import (
	"fmt"
	"html/template"
	"os"
	"slices"
	"sort"

	contentserver "contentserver/internal/posts"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/ast"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"gopkg.in/yaml.v3"
)

func mdToHTML(md []byte, printAst bool) []byte {
	extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock
	p := parser.NewWithExtensions(extensions)
	doc := p.Parse(md)

	if printAst {
		fmt.Print("--- AST tree:\n")
		ast.Print(os.Stdout, doc)
		fmt.Print("\n")
	}

	htmlFlags := html.CommonFlags | html.HrefTargetBlank
	opts := html.RendererOptions{Flags: htmlFlags}
	renderer := html.NewRenderer(opts)

	return markdown.Render(doc, renderer)
}

func getHTML(markdown []byte) template.HTML {
	return template.HTML(mdToHTML(markdown, false))
}

func GetPosts(postsDir string) map[string]contentserver.Post {
	posts := make(map[string]contentserver.Post)
	files, err := os.ReadDir(postsDir)
	fmt.Println("Reading posts from: ", postsDir)
	
	if err != nil {
		fmt.Println(err)
	}

	for _, f := range files {
		fmt.Println("Reading post: ", f.Name())
		if f.IsDir() {
			postSlug := f.Name()
			posts[postSlug] = GetPost(postsDir, postSlug)
		}
	}

	return posts
}

func GetPost(postsDir string, slug string) contentserver.Post {
	post := new(contentserver.Post)
	post.Slug = slug
	meta := GetMeta(postsDir + "/" + slug + "/meta.yaml")
	body := GetBody(postsDir + "/" + slug + "/post.md")
	post.Meta = *meta
	post.Body = body

	return *post
}

func PostsByCategory(posts *map[string]contentserver.Post) map[string][]contentserver.Post {
	postsByCategory := make(map[string][]contentserver.Post)

	for _, post := range *posts {
		for _, category := range post.Meta.Categories {
			postsByCategory[category] = append(postsByCategory[category], post)
		}
	}

	for category := range postsByCategory {
		sort.SliceStable(postsByCategory[category], func(i, j int) bool {
			return postsByCategory[category][i].Meta.Date.Time.Compare(postsByCategory[category][j].Meta.Date.Time) == -1
		})
	}

	return postsByCategory
}

func GetYARAPosts(posts []contentserver.Post) []contentserver.Post {

	sort.SliceStable(posts, func(i, j int) bool {
		return posts[i].Meta.Date.Time.Compare(posts[j].Meta.Date.Time) == -1
	})

	return posts
}

func GetCategories(posts *map[string]contentserver.Post) []string {
	categories := make([]string, 0)

	for _, post := range *posts {
		for _, category := range post.Meta.Categories {
			if !slices.Contains(categories, category) {
				categories = append(categories, category)
			}
		}
	}

	return categories
}

func GetBody(path string) template.HTML {
	data, err := os.ReadFile(path)

	if err != nil {
		fmt.Println(err)
	}

	return getHTML(data)

}

func GetMeta(path string) *contentserver.PostMeta {
	var meta contentserver.PostMeta

	data, err := os.ReadFile(path)

	if err != nil {
		fmt.Println(err)
	}

	if err := yaml.Unmarshal(data, &meta); err != nil {
		fmt.Println(err)
	}

	return &meta
}
