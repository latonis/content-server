package main

import (
	contentserver "contentserver/internal/create"
	"net/http"

	"github.com/gin-gonic/gin"
)

var posts map[string]contentserver.Post
var categories []string
var postsByCategory map[string][]contentserver.Post

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
	posts = contentserver.GetPosts()
	categories = contentserver.GetCategories(&posts)
	postsByCategory = contentserver.PostsByCategory(&posts)
	r.LoadHTMLGlob("templates/*")
	r.GET("/ping", GetHandler)
	r.GET("/api/v1/posts", PostsHandler)
	r.GET("/api/v1/posts/categories", CategoriesHandler)
	r.GET("/", HomeHandler)
	r.GET("/posts/:slug", PostHandler)
	r.Run("0.0.0.0:8080")
}

func HomeHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "base", nil)
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
	postsToSend := posts
	keys := make([]contentserver.Post, len(postsToSend))
	i := 0

	if c.Query("category") != "" {
		keys = postsByCategory[c.Query("category")]
	} else {
		for k := range postsToSend {
			if k == "about" {
				continue
			}
			keys[i] = posts[k]
			i++
		}
	}

	if c.Request.Header.Get("Hx-Request") == "true" {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<ul>"))
		for k := range keys {
			c.HTML(http.StatusOK, "list", Link{"/posts/" + keys[k].Slug, keys[k].Slug, false, ""})
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("</ul>"))
		return
	}

	c.JSON(http.StatusOK, keys)
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
