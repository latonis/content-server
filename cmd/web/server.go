package main

import (
	create "contentserver/internal/create"
	web "contentserver/internal/handlers"
	"net/http"

	"github.com/gin-gonic/gin"
)

var posts map[string]web.Post
var postsByDate []web.Post
var postsByCategory map[string][]web.Post
var about web.Post
var categories []string
var YARAPosts2024 []web.Post

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
	postsByDate = web.GetPostsByDate(posts)
	postsByCategory = web.GetPostsByCategory(posts)
	categories = web.GetCategories(posts)
	_ = web.GetPostsByCategory(posts)

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
		Data:        val,
	}

	c.HTML(http.StatusOK, "post", container)
}
