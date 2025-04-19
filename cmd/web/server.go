package main

import (
	create "contentserver/internal/format"
	web "contentserver/internal/handlers"
	"net/http"

	"github.com/gin-gonic/gin"
)

var posts map[string]web.Post
var postsByDate []web.Post
var postsByCategory map[string][]web.Post
var about web.Post
var categories []string
var YARAPosts2024 map[string]web.Post

type Container struct {
	CurrentPath string
	Title       string
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
	postsByDate = web.GetPostsByDate(posts)
	YARAPosts2024, err = create.GetPosts("content/posts/yara-2024")
	postsByCategory = web.GetPostsByCategory(posts)
	categories = web.GetCategories(posts)

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
	r.GET("/posts/categories/:category", PostsHandler)
	r.GET("/api/v1/categories/:category", APICategoriesHandler)

	r.Run("0.0.0.0:8080")
}

func HomeHandler(c *gin.Context) {

	topPosts := make([]web.Post, 0)
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
		Title:       "Home",
		Data:        map[string]any{"posts": topPosts},
	}

	c.HTML(http.StatusOK, "home", container)
}

func aboutHandler(c *gin.Context) {
	container := Container{
		CurrentPath: "/about",
		Title:       "About",
		Data:        about,
	}

	c.HTML(http.StatusOK, "about", container)
}

func APICategoriesHandler(c *gin.Context) {
	category := c.Param("category")
	posts_to_send, ok := postsByCategory[category]

	if !ok {
		c.HTML(http.StatusNotFound, "category not found", nil)
		return
	}

	for i := range posts_to_send {
		c.HTML(http.StatusOK, "card", posts_to_send[i])
	}
}

func PostsHandler(c *gin.Context) {
	category := c.Param("category")
	posts := postsByDate

	if category != "" {
		posts = postsByCategory[category]
	}

	container := Container{
		CurrentPath: "/posts",
		Title:       "Posts",
		Data:        map[string]any{"posts": posts, "categories": categories},
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
		Title:       val.Meta.Title,
		Data:        val,
	}

	c.HTML(http.StatusOK, "post", container)
}
