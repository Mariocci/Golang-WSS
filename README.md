# WebSocket Server

This is a simple WebSocket server implemented in Go (Golang).

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Endpoints](#endpoints)
- [License](#license)

## Introduction

This WebSocket server provides a simple backend for managing WebSocket connections. It includes authentication and authorization mechanisms, as well as various endpoints for handling WebSocket messages and HTTP requests.

## Features

- WebSocket server implementation in Go
- Authentication and authorization using JSON Web Tokens (JWT)
- Register and login endpoints for user management
- Example WebSocket endpoints for handling messages
- Middleware for authorization check on HTTP endpoints

## Installation

To install and run the WebSocket server, follow these steps:

1. Clone this repository to your local machine.
2. Install Go if you haven't already: [Go Installation Instructions](https://golang.org/doc/install)
3. Navigate to the project directory.
4. Run `go run main.go` to start the server.

## Usage

Once the server is running, you can interact with it using WebSocket clients or HTTP requests. Here are some example usage scenarios:

- Register a new user: Send a POST request to `/register` with a JSON body containing the username and password.
- Login as a user: Send a POST request to `/login` with a JSON body containing the username and password. This will return a JWT token.
- Connect to WebSocket endpoint: Use a WebSocket client to connect to `ws://localhost:8080/ws` with the JWT token appended as a query parameter (`?token=<your_token>`).
- Send messages: Once connected to the WebSocket endpoint, you can send and receive messages.

## Endpoints

- `/register`: POST request to register a new user.
- `/login`: POST request to login as an existing user and receive a JWT token.
- `/ws`: WebSocket endpoint for establishing WebSocket connections.
- `/endpoint1`, `/endpoint2`, `/endpoint3`: Example HTTP endpoints protected by JWT authorization middleware.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
