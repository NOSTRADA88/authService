package main 

import (
	"github.com/NOSTRADA88/authService/internal/authService/http"
)

func main() {
	err := http.StartServer()
	if err != nil {
		panic(err)
	}
}