package wildcat

import (
	"bytes"
	"io"
	"strconv"

	"github.com/vektra/errors"
)

const OptimalBufferSize = 1500

type header struct {
	Name  []byte
	Value []byte
}

type HTTPParser struct {
	subscribeHeader       [][]byte
	subscribeAllHeader    bool
	Method, Path, Version []byte

	Headers      []header
	TotalHeaders int

	host     []byte
	hostRead bool

	contentLength     int64
	contentLengthRead bool
}

const DefaultHeaderSlice = 4

// Create a new parser
func NewHTTPParser() *HTTPParser {
	return NewSizedHTTPParser(DefaultHeaderSlice)
}

// Create a new parser allocating size for size headers
func NewSizedHTTPParser(size int) *HTTPParser {
	return &HTTPParser{
		Headers:            make([]header, size),
		TotalHeaders:       size,
		contentLength:      -1,
		subscribeAllHeader: true,
	}
}

var (
	ErrBadProto    = errors.New("bad protocol")
	ErrMissingData = errors.New("missing data")
	ErrUnsupported = errors.New("unsupported http feature")
)

const (
	eNextHeader int = iota
	eNextHeaderN
	eHeader
	eHeaderValueSpace
	eHeaderValue
	eHeaderValueN
	eMLHeaderStart
	eMLHeaderValue
)

// Parse the buffer as an HTTP Request. The buffer must contain the entire
// request or Parse will return ErrMissingData for the caller to get more
// data. (this thusly favors getting a completed request in a single Read()
// call).
//
// Returns the number of bytes used by the header (thus where the body begins).
// Also can return ErrUnsupported if an HTTP feature is detected but not supported.
func (hp *HTTPParser) Parse(input []byte) (int, error) {
	var headers int
	var path int
	var ok bool

	total := len(input)

method:
	for i := 0; i < total; i++ {
		switch input[i] {
		case ' ', '\t':
			hp.Method = input[0:i]
			ok = true
			path = i + 1
			break method
		}
	}

	if !ok {
		return 0, ErrMissingData
	}

	var version int

	ok = false

path:
	for i := path; i < total; i++ {
		switch input[i] {
		case ' ', '\t':
			ok = true
			hp.Path = input[path:i]
			version = i + 1
			break path
		}
	}

	if !ok {
		return 0, ErrMissingData
	}

	var readN bool

	ok = false
loop:
	for i := version; i < total; i++ {
		c := input[i]

		switch readN {
		case false:
			switch c {
			case '\r':
				hp.Version = input[version:i]
				readN = true
			case '\n':
				hp.Version = input[version:i]
				headers = i + 1
				ok = true
				break loop
			}
		case true:
			if c != '\n' {
				return 0, errors.Context(ErrBadProto, "missing newline in version")
			}
			headers = i + 1
			ok = true
			break loop
		}
	}

	if !ok {
		return 0, ErrMissingData
	}

	var h int

	var headerName []byte

	state := eNextHeader

	start := headers

	for i := headers; i < total; i++ {
		switch state {
		case eNextHeader:
			switch input[i] {
			case '\r':
				state = eNextHeaderN
			case '\n':
				return i + 1, nil
			case ' ', '\t':
				state = eMLHeaderStart
			default:
				start = i
				state = eHeader
			}
		case eNextHeaderN:
			if input[i] != '\n' {
				return 0, ErrBadProto
			}

			return i + 1, nil
		case eHeader:
			if input[i] == ':' {
				headerName = input[start:i]
				state = eHeaderValueSpace
			}
		case eHeaderValueSpace:
			switch input[i] {
			case ' ', '\t':
				continue
			}

			start = i
			state = eHeaderValue
		case eHeaderValue:
			switch input[i] {
			case '\r':
				state = eHeaderValueN
			case '\n':
				state = eNextHeader
			default:
				continue
			}
			if headerName[0] == 'C' && bytes.Equal(headerName, cContentLength) {
				i, err := strconv.ParseInt(string(input[start:i]), 10, 0)
				if err == nil {
					hp.contentLength = i
				}
				hp.contentLengthRead = true
				hp.addHeader(h, headerName, input[start:i])
			} else if hp.subscribeAllHeader {
				hp.addHeader(h, headerName, input[start:i])
			} else {
				for _, b := range hp.subscribeHeader {
					if headerName[0] == b[0] {
						if bytes.Equal(headerName, b) {
							hp.addHeader(h, headerName, input[start:i])
							break
						}
					}
				}
			}
			h++
		case eHeaderValueN:
			if input[i] != '\n' {
				return 0, ErrBadProto
			}
			state = eNextHeader

		case eMLHeaderStart:
			switch input[i] {
			case ' ', '\t':
				continue
			}

			start = i
			state = eMLHeaderValue
		case eMLHeaderValue:
			switch input[i] {
			case '\r':
				state = eHeaderValueN
			case '\n':
				state = eNextHeader
			default:
				continue
			}

			cur := hp.Headers[h-1].Value

			newheader := make([]byte, len(cur)+1+(i-start))
			copy(newheader, cur)
			copy(newheader[len(cur):], []byte(" "))
			copy(newheader[len(cur)+1:], input[start:i])

			hp.Headers[h-1].Value = newheader
		}
	}

	return 0, ErrMissingData
}

func (hp *HTTPParser) addHeader(headerIndex int, headerName, headerValue []byte) {
	hp.Headers[headerIndex] = header{headerName, headerValue}
	if headerIndex+1 == hp.TotalHeaders {
		newHeaders := make([]header, hp.TotalHeaders+DefaultHeaderSlice)
		copy(newHeaders, hp.Headers)
		hp.Headers = newHeaders
		hp.TotalHeaders += DefaultHeaderSlice
	}
}

func (hp *HTTPParser) Reset() {
	for _, h := range hp.Headers {
		h.Name = nil
		h.Value = nil
	}
	hp.hostRead = false
	hp.contentLengthRead = false
	hp.contentLength = -1
	if len(hp.Headers) > len(hp.subscribeHeader)+1 {
		hp.Headers = hp.Headers[:len(hp.subscribeHeader)+1]
	}
}

func (hp *HTTPParser) SubscribeAllHeader(sub bool) {
	hp.subscribeAllHeader = sub
}

func (hp *HTTPParser) SubscribeHeader(name []byte) {
	hp.subscribeHeader = append(hp.subscribeHeader, name)
}

// Return a value of a header matching name.
func (hp *HTTPParser) FindHeader(name []byte) []byte {
	for _, header := range hp.Headers {
		if bytes.Equal(header.Name, name) {
			return header.Value
		}
	}

	for _, header := range hp.Headers {
		if bytes.EqualFold(header.Name, name) {
			return header.Value
		}
	}

	return nil
}

// Return all values of a header matching name.
func (hp *HTTPParser) FindAllHeaders(name []byte) [][]byte {
	var headers [][]byte

	for _, header := range hp.Headers {
		if bytes.EqualFold(header.Name, name) {
			headers = append(headers, header.Value)
		}
	}

	return headers
}

var cHost = []byte("Host")

// Return the value of the Host header
func (hp *HTTPParser) Host() []byte {
	if hp.hostRead {
		return hp.host
	}

	hp.hostRead = true
	hp.host = hp.FindHeader(cHost)
	return hp.host
}

var cContentLength = []byte("Content-Length")

// Return the value of the Content-Length header.
// A value of -1 indicates the header was not set.
func (hp *HTTPParser) ContentLength() int64 {
	if hp.contentLengthRead {
		return hp.contentLength
	}

	header := hp.FindHeader(cContentLength)
	if header != nil {
		i, err := strconv.ParseInt(string(header), 10, 0)
		if err == nil {
			hp.contentLength = i
		}
	}

	hp.contentLengthRead = true
	return hp.contentLength
}

func (hp *HTTPParser) BodyReader(rest []byte, in io.ReadCloser) io.ReadCloser {
	return BodyReader(hp.ContentLength(), rest, in)
}

var cGet = []byte("GET")

func (hp *HTTPParser) Get() bool {
	return bytes.Equal(hp.Method, cGet)
}

var cPost = []byte("POST")
var cPut = []byte("PUT")

func (hp *HTTPParser) Post() bool {
	return bytes.Equal(hp.Method, cPost)
}

func (hp *HTTPParser) Put() bool {
	return bytes.Equal(hp.Method, cPut)
}

func (hp *HTTPParser) PostOrPut() bool {
	return hp.Post() || hp.Put()
}
