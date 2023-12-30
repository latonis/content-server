package main

import (
	contentserver "contentserver/internal/create"
	"net/http"

	"github.com/gin-gonic/gin"
)

var posts map[string]contentserver.Post

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Static("/static", "./static")
	posts = contentserver.GetPosts()
	r.LoadHTMLGlob("templates/*")
	r.GET("/ping", GetHandler)
	r.GET("/api/v1/posts", AllPostsHandler)
	r.GET("/", HomeHandler)
	r.GET("/posts/:slug", PostHandler)
	r.Run("0.0.0.0:8080")
}

func HomeHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "base", nil)
}

func AllPostsHandler(c *gin.Context) {
	keys := make([]string, len(posts))
	i := 0

	for k := range posts {
		if k == "about" {
			continue
		}
		keys[i] = k
		i++
	}

	if c.Request.Header.Get("Hx-Request") == "true" {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<ul>"))
		for k := range keys {
			c.HTML(http.StatusOK, "list", keys[k])
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
