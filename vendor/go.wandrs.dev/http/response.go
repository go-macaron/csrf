package http

import (
	"fmt"
	"html/template"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-logr/logr"
	"github.com/unrolled/render"
)

type ResponseWriter interface {
	http.ResponseWriter
	R() Request

	// render functions
	TemplateLookup(t string) *template.Template
	Render(e render.Engine, data interface{})
	Data(status int, v []byte)
	HTML(status int, name string, binding interface{}, htmlOpt ...render.HTMLOptions)
	JSON(status int, v interface{})
	JSONP(status int, callback string, v interface{})
	Text(status int, v string)
	XML(status int, v interface{})
	Error(status int, contents ...interface{})

	// extended ResponseWriter methods
	Written() bool
	// Status returns the HTTP status of the request, or 0 if one has not
	// yet been sent.
	Status() int
	// BytesWritten returns the total number of bytes sent to the client.
	BytesWritten() int

	// API error
	APIError(err error) int

	// misc render/response functions
	Redirect(location string, status ...int)
	RedirectToFirst(appURL, appSubURL string, location ...string)
	HTMLString(name string, binding interface{}, htmlOpt ...render.HTMLOptions) (string, error)
	ServeContent(name string, r io.ReadSeeker, params ...interface{})
	ServeFile(file string, names ...string)
}

type response struct {
	http.ResponseWriter
	req    Request
	r      *render.Render
	logger logr.Logger
}

var _ ResponseWriter = &response{}

func NewResponseWriter(w http.ResponseWriter, req *http.Request, r *render.Render, logger logr.Logger) ResponseWriter {
	return &response{
		ResponseWriter: w,
		req:            &request{req: req},
		r:              r,
		logger:         logger,
	}
}

func (w *response) R() Request {
	return w.req
}

func (w *response) TemplateLookup(t string) *template.Template {
	return w.r.TemplateLookup(t)
}

func (w *response) Render(e render.Engine, data interface{}) {
	if err := w.r.Render(w, e, data); err != nil {
		if log := middleware.GetLogEntry(w.R().Request()); log != nil {
			log.Panic(err.Error(), nil)
		}
	}
}

func (w *response) Data(status int, v []byte) {
	if err := w.r.Data(w, status, v); err != nil {
		if log := middleware.GetLogEntry(w.R().Request()); log != nil {
			log.Panic(err.Error(), nil)
		}
	}
}

func (w *response) HTML(status int, name string, binding interface{}, htmlOpt ...render.HTMLOptions) {
	if err := w.r.HTML(w, status, name, binding, htmlOpt...); err != nil {
		if log := middleware.GetLogEntry(w.R().Request()); log != nil {
			log.Panic(err.Error(), nil)
		}
	}
}

func (w *response) JSON(status int, v interface{}) {
	if err := w.r.JSON(w, status, v); err != nil {
		if log := middleware.GetLogEntry(w.R().Request()); log != nil {
			log.Panic(err.Error(), nil)
		}
	}
}

func (w *response) JSONP(status int, callback string, v interface{}) {
	if err := w.r.JSONP(w, status, callback, v); err != nil {
		if log := middleware.GetLogEntry(w.R().Request()); log != nil {
			log.Panic(err.Error(), nil)
		}
	}
}

func (w *response) Text(status int, v string) {
	if err := w.r.Text(w, status, v); err != nil {
		if log := middleware.GetLogEntry(w.R().Request()); log != nil {
			log.Panic(err.Error(), nil)
		}
	}
}

func (w *response) XML(status int, v interface{}) {
	if err := w.r.XML(w, status, v); err != nil {
		if log := middleware.GetLogEntry(w.R().Request()); log != nil {
			log.Panic(err.Error(), nil)
		}
	}
}

// Error if length of contents is more than 1, then the
// first content will be considered as title and the
// second content will be considered as the error
func (w *response) Error(status int, contents ...interface{}) {
	v := http.StatusText(status)

	var title string
	var obj interface{}

	if len(contents) > 1 {
		title = fmt.Sprintf("%v", contents[0])
		obj = contents[1]
	} else if len(contents) > 0 {
		obj = contents[0]
	}

	if err, ok := obj.(error); ok {
		v = err.Error()
	} else {
		v = fmt.Sprintf("%v", obj)
	}

	if len(title) > 0 && w.logger.GetSink() != nil {
		// log the error with the title
		w.logger.Error(fmt.Errorf(v), title)
	}

	http.Error(w, v, status)
}

// Written returns true if there are something sent to web browser
func (w *response) Written() bool {
	if ww, ok := w.ResponseWriter.(middleware.WrapResponseWriter); ok {
		return ww.Status() > 0
	}
	panic("chi: unsupported method, r.Use(middleware.Logger) to implement")
}

// Status returns the HTTP status of the request, or 0 if one has not
// yet been sent.
func (w *response) Status() int {
	if ww, ok := w.ResponseWriter.(middleware.WrapResponseWriter); ok {
		return ww.Status()
	}
	panic("chi: unsupported method, r.Use(middleware.Logger) to implement")
}

// BytesWritten returns the total number of bytes sent to the client.
func (w *response) BytesWritten() int {
	if ww, ok := w.ResponseWriter.(middleware.WrapResponseWriter); ok {
		return ww.BytesWritten()
	}
	panic("chi: unsupported method, r.Use(middleware.Logger) to implement")
}
