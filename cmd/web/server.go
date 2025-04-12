package main

import (
	create "contentserver/internal/create"
	contentserver "contentserver/internal/handlers"
	"net/http"

	"github.com/gin-gonic/gin"
)

var posts map[string]contentserver.Post
var about contentserver.Post
var categories []string
var YARAPosts2024 []contentserver.Post

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

	r.Run("0.0.0.0:8080")
}

func HomeHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "home", nil)
}

func aboutHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "about", about)
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
	c.JSON(http.StatusOK, categories)
}

func PostsHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "posts", posts)
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

	c.HTML(http.StatusOK, "base", val)
}
