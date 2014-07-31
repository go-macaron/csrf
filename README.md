csrf
====

Middleware csrf generates and validates csrf tokens for [Macaron](https://github.com/Unknwon/macaron).

[API Reference](https://gowalker.org/github.com/macaron-contrib/csrf)

### Installation

	go get github.com/macaron-contrib/csrf
	
## Usage

```go
package main

import (
    "net/http"
    
    "github.com/Unknown/macaron"
    "github.com/macaron-contrib/csrf"
    "github.com/macaron-contrib/session"
)

func main() {
    m := macaron.Classic()
    m.Use(session.Sessioner())
    m.Use(csrf.Generate(csrf.Options{
        Secret:     "token123",
        SessionKey: "userID",
        // Custom error response.
        ErrorFunc: func(w http.ResponseWriter) {
            http.Error(w, "CSRF token validation failed", http.StatusBadRequest)
        },
    }))
    m.Use(macaron.Renderer())

    // Simulate the authentication of a session. If userID exists redirect
    // to a form that requires csrf protection.
    m.Get("/", func(ctx *macaron.Context, s sessions.Session) {
        if s.Get("userID") == nil {
            ctx.Redirect("/login", 302)
            return
        }
        ctx.Redirect("/protected", 302)
    })

    // Set userID for the session.
    m.Get("/login", func(ctx *macaron.Context, s sessions.Session) {
        s.Set("userID", "123456")
        ctx.Redirect("/", 302)
    })

    // Render a protected form. Passing a csrf token by calling x.GetToken()
    m.Get("/protected", func(ctx *macaron.Context, s sessions.Session, x csrf.CSRF) {
        if s.Get("userID") == nil {
            ctx.Redirect("/login", 401)
            return
        }
        // Pass token to the protected template.
        ctx.HTML(200, "protected", x.GetToken())
    })

    // Apply csrf validation to route.
    m.Post("/protected", csrf.Validate, func(ctx *macaron.Context, s sessions.Session) {
        if s.Get("userID") != nil {
            ctx.HTML(200, "result", "You submitted a valid token")
            return
        }
        ctx.Redirect("/login", 401)
    })

    m.Run()
}
```

## License

This project is under Apache v2 License. See the [LICENSE](LICENSE) file for the full license text.