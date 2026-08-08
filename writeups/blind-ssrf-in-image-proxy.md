---
title: Blind SSRF in image proxy
parent: Writeups
nav_order: 3
tags: [ssrf, cloudfront, image proxy]
---

# Blind SSRF in image proxy
{: .no_toc }

**Severity:** Medium, CVSS 5.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N)  
**Vulnerability Class:** CWE-918: Server-Side Request Forgery (SSRF)  
**Impact:** Internal network enumeration  
**Relevant Resources:** [Orange Tsai BlackHat Talk](https://www.youtube.com/watch?v=CIhHpkybYsY), [Slides](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf), [Uniform Resource Identifier RFC](https://datatracker.ietf.org/doc/html/rfc3986)

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Summary
A blind SSRF vulnerability was found in an image proxy, making it possible to enumerate internal networks

## Vulnerability Details

The main app of the company sometimes used a proxy to fetch images like users profile pictures. The proxy is given a URL directly inside the path, for example

```
https://image-proxy.company.com/http://some-url/
```

which it then tries to fetch. 

A protection is in place so that only URLs from a certain cloudfront domain could be used, otherwise the proxy would return the error `403: URL not in allowlist`.

The vulnerability lies in a URL parsing discrepancy between the component that checks if the URL is in the allowlist and the one that actually makes the request. Specifically, using a URL like

```
https://image-proxy.company.com/http://target_host:port#@123.cloudfront.net/path/to/an/image
```

would cause the proxy to make a HTTP request to `target_host:port`.

The reason this happens is likely because the "allowlist checker" incorrectly treats `#` as part of the `username:password` combination, which goes against the RFC, as `#` is considered a reserved character.

The fetching components instead treats it as a URL fragment, ignoring everything that comes after

## Attempts at Exploitation
The exploitability and impact of this vulnerability are very limited. The "blind" in the title stems from the fact that, unless specific conditions are met, the proxy just returns with the error `400: Not an Image`.

Those conditions are:

1. The filename ends with `jpg`, `jpeg`, `png`, `webp` or `svg`
2. The file begins with the appropriate magic bytes, according to the file extension
3. The upstream server responds with the appropriate MIME type.

I tried to bypass this in several ways, all of them resulting in failure:

- Pointing the proxy to my server, which responded with a 30X redirect but also sent the correct Content-Type and some magic bytes
- Hosting an SVG with a Server Side XSS payload, which failed because svgs weren't rendered
- Using increasing 30X status codes, which I took from [this research](https://slcyber.io/research-center/novel-ssrf-technique-involving-http-redirect-loops/), but the behaviour didn't change

In the end I was only able to use it to enumerate internal IP:PORT combinations
