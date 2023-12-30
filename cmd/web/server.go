package main

import (
	contentserver "contentserver/internal/create"
	"net/http"

	"github.com/gin-gonic/gin"
)

var posts map[string]contentserver.Post

func main() {
	r := gin.Default()
	posts = contentserver.GetPosts()
	r.LoadHTMLGlob("templates/*")
	r.GET("/ping", GetHandler)
	r.GET("/:slug", PostHandler)
	r.Run("localhost:8080")

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
