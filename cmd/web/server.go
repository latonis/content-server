package main

import (
	create "contentserver/internal/create"
	contentserver "contentserver/internal/handlers"
	"net/http"

	"github.com/gin-gonic/gin"
)

var posts map[string]contentserver.Post
var postsByDate []contentserver.Post
var about contentserver.Post
var categories []string
var YARAPosts2024 []contentserver.Post

type Container struct {
	CurrentPath string
	Data        any
}

type Link struct {
	Ref    string
	Val    string
	Htmx   bool
	Target string
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Static("/static", "./static")
	r.StaticFile("/favicon.png", "./static/favicon.png")
	var err error

	posts, err = create.GetPosts("content/posts")
	postsByDate = contentserver.GetPostsByDate(posts)
	categories = contentserver.GetCategories(posts)
	_ = contentserver.GetPostsByCategory(posts)

	if err != nil {
		panic(err)
	}

	about, err = create.GetPost("content", "about")

	if err != nil {
		panic(err)
	}

	r.LoadHTMLGlob("templates/*")

	r.GET("/", HomeHandler)
	r.HEAD("/", HomeHandler)
	r.GET("/about", aboutHandler)
	r.GET("/posts", PostsHandler)
	r.GET("/posts/:slug", PostHandler)

	r.Run("0.0.0.0:8080")
}

func HomeHandler(c *gin.Context) {

	topPosts := make([]contentserver.Post, 0)
	maxPosts := min(3, len(posts))
	i := 0
	for _, val := range posts {
		if i >= maxPosts {
			break
		}

		topPosts = append(topPosts, val)
		i++
	}

	container := Container{
		CurrentPath: "/",
		Data:        map[string]any{"posts": topPosts},
	}

	c.HTML(http.StatusOK, "home", container)
}

func aboutHandler(c *gin.Context) {
	container := Container{
		CurrentPath: "/about",
		Data:        about,
	}

	c.HTML(http.StatusOK, "about", container)
}

func CategoriesHandler(c *gin.Context) {
	if c.Request.Header.Get("Hx-Request") == "true" {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<ul>"))
		for k := range categories {
			c.HTML(http.StatusOK, "list", Link{"/api/v1/posts?category=" + categories[k], categories[k], true, "#posts"})
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("</ul>"))
		return
	}

	container := Container{
		CurrentPath: "/categories",
		Data:        categories,
	}

	c.JSON(http.StatusOK, container)
}

func PostsHandler(c *gin.Context) {
	container := Container{
		CurrentPath: "/posts",
		Data:        map[string]any{"posts": postsByDate, "categories": categories},
	}

	c.HTML(http.StatusOK, "posts", container)
}

func GetHandler(c *gin.Context) {
	c.JSON(http.StatusOK, "hullo")
}

func PostHandler(c *gin.Context) {
	val, ok := posts[c.Param("slug")]

	if !ok {
		c.JSON(http.StatusNotFound, "post not found")
		return
	}

	container := Container{
		CurrentPath: "/posts/" + c.Param("slug"),
		Data:        val,
	}

	c.HTML(http.StatusOK, "post", container)
}
