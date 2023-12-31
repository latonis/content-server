package contentserver

import (
	"fmt"
	"html/template"
	"os"
	"slices"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/ast"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"gopkg.in/yaml.v3"
)

type PostMeta struct {
	Title       string   `yaml:"title"`
	Date        string   `yaml:"date"`
	Categories  []string `yaml:"categories"`
	Description string   `yaml:"description"`
}

type Post struct {
	Slug string
	Meta PostMeta
	Body template.HTML
}

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

func GetPosts() map[string]Post {
	posts := make(map[string]Post)
	files, err := os.ReadDir("posts")

	if err != nil {
		fmt.Println(err)
	}

	for _, f := range files {
		if f.IsDir() {
			postSlug := f.Name()
			post := new(Post)
			post.Slug = postSlug
			meta := GetMeta("posts/" + postSlug + "/meta.yaml")
			body := GetBody("posts/" + postSlug + "/post.md")
			post.Meta = *meta
			post.Body = body
			posts[postSlug] = *post
		}
	}
	return posts
}

func PostsByCategory(posts *map[string]Post) map[string][]Post {
	postsByCategory := make(map[string][]Post)

	for _, post := range *posts {
		for _, category := range post.Meta.Categories {
			postsByCategory[category] = append(postsByCategory[category], post)
		}
	}

	return postsByCategory
}

func GetCategories(posts *map[string]Post) []string {
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

func GetMeta(path string) *PostMeta {
	var meta PostMeta

	data, err := os.ReadFile(path)

	if err != nil {
		fmt.Println(err)
	}

	if err := yaml.Unmarshal(data, &meta); err != nil {
		fmt.Println(err)
	}

	return &meta
}

func main() {
	posts := GetPosts()

	for _, post := range posts {
		fmt.Println(post)
	}
}
