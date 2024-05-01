package main

import (
	"fmt"
	"net/http"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins
	},
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Error upgrading to WebSocket:", err)
		return
	}
	defer conn.Close()

	// Echo messages back to the client
	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("Error reading message:", err)
			return
		}
		if err := conn.WriteMessage(messageType, p); err != nil {
			fmt.Println("Error writing message:", err)
			return
		}
	}
}

func main() {
	http.HandleFunc("/ws", wsHandler)
	fmt.Println("Server is running on https://localhost:8080")
	err := http.ListenAndServeTLS(":8080", "server.crt", "server.key", nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}
