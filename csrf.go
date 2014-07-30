// Copyright 2013 Martini Authors
// Copyright 2014 Unknwon
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package csrf is a middleware that generates and validates csrf tokens for Macaron.
package csrf

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Unknwon/macaron"
	"github.com/macaron-contrib/session"
)

// CSRF is used to get the current token and validate a suspect token.
type CSRF interface {
	// Return HTTP header to search for token.
	GetHeaderName() string
	// Return form value to search for token.
	GetFormName() string
	// Return cookie name to search for token.
	GetCookieName() string
	// Return the token.
	GetToken() string
	// Validate by token.
	ValidToken(t string) bool
	// Error replies to the request with a custom function when ValidToken fails.
	Error(w http.ResponseWriter)
}

type csrf struct {
	// Header name value for setting and getting csrf token.
	Header string
	// Form name value for setting and getting csrf token.
	Form string
	// Cookie name value for setting and getting csrf token.
	Cookie string
	// Token generated to pass via header, cookie, or hidden form value.
	Token string
	// This value must be unique per user.
	ID string
	// Secret used along with the unique id above to generate the Token.
	Secret string
	// ErrorFunc is the custom function that replies to the request when ValidToken fails.
	ErrorFunc func(w http.ResponseWriter)
}

// Returns the name of the HTTP header for csrf token.
func (c *csrf) GetHeaderName() string {
	return c.Header
}

// Returns the name of the form value for csrf token.
func (c *csrf) GetFormName() string {
	return c.Form
}

// Returns the name of the cookie for csrf token.
func (c *csrf) GetCookieName() string {
	return c.Cookie
}

// Returns the current token. This is typically used
// to populate a hidden form in an HTML template.
func (c *csrf) GetToken() string {
	return c.Token
}

// Validates the passed token against the existing Secret and ID.
func (c *csrf) ValidToken(t string) bool {
	return ValidToken(t, c.Secret, c.ID, "POST")
}

// Error replies to the request when ValidToken fails.
func (c *csrf) Error(w http.ResponseWriter) {
	c.ErrorFunc(w)
}

// Options maintains options to manage behavior of Generate.
type Options struct {
	// The global secret value used to generate Tokens.
	Secret string
	// HTTP header used to set and get token.
	Header string
	// Form value used to set and get token.
	Form string
	// Cookie value used to set and get token.
	Cookie string
	// Key used for getting the unique ID per user.
	SessionKey string
	// If true, send token via X-CSRFToken header.
	SetHeader bool
	// If true, send token via _csrf cookie.
	SetCookie bool
	// Set the Secure flag to true on the cookie.
	Secure bool
	// The function called when Validate fails.
	ErrorFunc func(w http.ResponseWriter)
}

const domainReg = `/^\.?[a-z\d]+(?:(?:[a-z\d]*)|(?:[a-z\d\-]*[a-z\d]))(?:\.[a-z\d]+(?:(?:[a-z\d]*)|(?:[a-z\d\-]*[a-z\d])))*$/`

// Generate maps CSRF to each request. If this request is a Get request, it will generate a new token.
// Additionally, depending on options set, generated tokens will be sent via Header and/or Cookie.
func Generate(opts *Options) macaron.Handler {
	return func(ctx *macaron.Context, sess session.Store) {
		if opts.Header == "" {
			opts.Header = "X-CSRFToken"
		}
		if opts.Form == "" {
			opts.Form = "_csrf"
		}
		if opts.Cookie == "" {
			opts.Cookie = "_csrf"
		}
		if opts.ErrorFunc == nil {
			opts.ErrorFunc = func(w http.ResponseWriter) {
				http.Error(w, "Invalid csrf token.", http.StatusBadRequest)
			}
		}

		x := &csrf{
			Secret:    opts.Secret,
			Header:    opts.Header,
			Form:      opts.Form,
			Cookie:    opts.Cookie,
			ErrorFunc: opts.ErrorFunc,
		}
		ctx.MapTo(x, (*CSRF)(nil))

		uid := sess.Get(opts.SessionKey)
		if uid == nil {
			return
		}
		switch uid.(type) {
		case string:
			x.ID = uid.(string)
		case int64:
			x.ID = strconv.FormatInt(uid.(int64), 10)
		default:
			return
		}

		if ctx.Req.Method != "GET" || ctx.Req.Header.Get("Origin") != "" {
			return
		}

		// If cookie present, map existing token, else generate a new one.
		if ex, err := ctx.Req.Cookie(opts.Cookie); err == nil && ex.Value != "" {
			x.Token = ex.Value
		} else {
			x.Token = GenerateToken(x.Secret, x.ID, "POST")
			if opts.SetCookie {
				expire := time.Now().AddDate(0, 0, 1)
				// Verify the domain is valid. If it is not, set as empty.
				domain := strings.Split(ctx.Req.Host, ":")[0]
				if ok, err := regexp.Match(domainReg, []byte(domain)); !ok || err != nil {
					domain = ""
				}

				cookie := &http.Cookie{
					Name:       opts.Cookie,
					Value:      x.Token,
					Path:       "/",
					Domain:     domain,
					Expires:    expire,
					RawExpires: expire.Format(time.UnixDate),
					MaxAge:     0,
					Secure:     opts.Secure,
					HttpOnly:   false,
					Raw:        fmt.Sprintf("%s=%s", opts.Cookie, x.Token),
					Unparsed:   []string{fmt.Sprintf("token=%s", x.Token)},
				}
				http.SetCookie(ctx.Resp, cookie)
			}
		}

		if opts.SetHeader {
			ctx.Resp.Header().Add(opts.Header, x.Token)
		}
	}

}

// Validate should be used as a per route middleware. It attempts to get a token from a "X-CSRFToken"
// HTTP header and then a "_csrf" form value. If one of these is found, the token will be validated
// using ValidToken. If this validation fails, custom Error is sent in the reply.
// If neither a header or form value is found, http.StatusBadRequest is sent.
func Validate(r *http.Request, w http.ResponseWriter, x CSRF) {
	if token := r.Header.Get(x.GetHeaderName()); token != "" {
		if !x.ValidToken(token) {
			x.Error(w)
		}
		return
	}
	if token := r.FormValue(x.GetFormName()); token != "" {
		if !x.ValidToken(token) {
			x.Error(w)
		}
		return
	}

	http.Error(w, "Bad Request", http.StatusBadRequest)
	return
}
