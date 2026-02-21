package templates

import "strconv"

func itoa(n int) string {
	return strconv.Itoa(n)
}

func faviconDataURI() string {
	return "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='16' fill='%23e94560'/><text x='50' y='68' font-size='48' font-weight='bold' font-family='sans-serif' fill='white' text-anchor='middle'>KST</text></svg>"
}
