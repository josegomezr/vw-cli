package shortcuts

import (
	"net/url"
)

func QSFromURL(inputurl string) (url.Values, error) {
	url, err := url.Parse(inputurl)
	if err != nil {
		return nil, err
	}
	return url.Query(), nil
}
