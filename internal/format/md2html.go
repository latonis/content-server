package contentserver

import (
	"fmt"
	"html/template"
	"os"
	"sort"

	contentserver "contentserver/internal/handlers"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/ast"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"gopkg.in/yaml.v3"
)

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return data, nil
}

func mdToHTML(md []byte, printAst bool) ([]byte, error) {
	extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock
	p := parser.NewWithExtensions(extensions)
	doc := p.Parse(md)

	if printAst {
		fmt.Println("--- AST tree:")
		ast.Print(os.Stdout, doc)
		fmt.Println()
	}

	htmlFlags := html.CommonFlags | html.HrefTargetBlank
	opts := html.RendererOptions{Flags: htmlFlags}
	renderer := html.NewRenderer(opts)

	return markdown.Render(doc, renderer), nil
}

func getHTML(markdown []byte) (template.HTML, error) {
	htmlBytes, err := mdToHTML(markdown, false)
	if err != nil {
		return "", err
	}
	return template.HTML(htmlBytes), nil
}

func GetPosts(postsDir string) (map[string]contentserver.Post, error) {
	posts := make(map[string]contentserver.Post)
	files, err := os.ReadDir(postsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read posts directory %s: %w", postsDir, err)
	}

	for _, f := range files {
		if f.IsDir() {
			_, err := os.Stat(fmt.Sprintf("%s/%s/meta.yaml", postsDir, f.Name()))
			if !os.IsNotExist(err) {
				postSlug := f.Name()
				post, err := GetPost(postsDir, postSlug)
				if err != nil {
					return nil, fmt.Errorf("failed to get post %s: %w", postSlug, err)
				}
				posts[postSlug] = post
			}
		}
	}
	return posts, nil
}

func GetPost(postsDir, slug string) (contentserver.Post, error) {
	meta, err := GetMeta(fmt.Sprintf("%s/%s/meta.yaml", postsDir, slug))
	if err != nil {
		return contentserver.Post{}, fmt.Errorf("failed to get metadata for post %s: %w", slug, err)
	}

	body, err := GetBody(fmt.Sprintf("%s/%s/post.md", postsDir, slug))
	if err != nil {
		return contentserver.Post{}, fmt.Errorf("failed to get body for post %s: %w", slug, err)
	}

	return contentserver.Post{
		Slug: slug,
		Meta: *meta,
		Body: body,
	}, nil
}

func GetYARAPosts(posts []contentserver.Post) []contentserver.Post {
	sort.SliceStable(posts, func(i, j int) bool {
		return posts[i].Meta.Date.Time.After(posts[j].Meta.Date.Time)
	})
	return posts
}

func GetBody(path string) (template.HTML, error) {
	data, err := readFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read body file %s: %w", path, err)
	}
	return getHTML(data)
}

func GetMeta(path string) (*contentserver.PostMeta, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file %s: %w", path, err)
	}

	var meta contentserver.PostMeta
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML from %s: %w", path, err)
	}

	return &meta, nil
}
