---
title: Full Read SSRF in file importer
parent: Writeups
nav_order: 1
tags: [ssrf, kubernetes, cloud, file import, webdav]
---

# Full Read SSRF in file importer
{: .no_toc }

**Severity:** High, CVSS 7.2 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N)  
**Vulnerability Class:** CWE-918: Server-Side Request Forgery (SSRF)  
**Impact:** Exposure of internal services, potential RCE  

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Summary
A SSRF vulnerability was found in the `Import from WebDAV` functionality, allowing attackers to enumerate and interact with internal services

## Vulnerability Details

The app, a file storage provider, offers the possibility to import files from a ```WebDAV``` server.     
The ```WebDAV``` protocol extends the standard HTTP protocol with additional verbs. From Wikipedia:


>WebDAV (Web Distributed Authoring and Versioning) is a set of extensions to the Hypertext Transfer Protocol (HTTP),
which allows user agents to collaboratively author contents directly in an HTTP web server by providing facilities for concurrency control and namespace operations,
 thus allowing the Web to be viewed as a writeable, collaborative medium and not just a read-only medium

In this particular case, the app sends a ```PROPFIND``` request to the user supplied URL, which is supposed to discover all resources on that server. 
The expected response is an XML document detailing the files hosted on the server, along with their sizes, and it looks like this

```
HTTP/1.1 207 Multi-Status
Content-Type: application/xml; charset="utf-8"

<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
      <D:href>FILENAME</D:href>
    <D:propstat>
      <D:prop>
        <D:getcontentlength>CONTENT_LENGTH</D:getcontentlength>
        <D:quota-available-bytes>10000</D:quota-available-bytes>
        <D:quota-used-bytes>100</D:quota-used-bytes>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
```

If a suitable response is received, the app will try to fetch the specified files via ```GET``` requests on the same server, expecting the specified content length, and if successful, will upload the response on the user's storage space

Standard SSRF protections were in place, but they did not account for redirection on the ```GET``` requests used to fetch the files, allowing attackers to reach internal networks. 

## Exploitation

Through trial and error, I've identified distinct behaviours to infer if the IP/host the importer is redirected to exist, and whether the specified port is open. Specifically:

- ~5 ```GET``` requests in an instant, then one request every 2 seconds for ~10 minutes means the host exists, but the port is closed.
- 1 ```GET``` request every minute means the host is down
- 1 ```GET``` request every two seconds and one ```PROPFIND``` request every 10 ```GET``` requests means the host exists and the port is open, but an erroneus Content-Length given in the initial ```PROPFIND``` response causes the importer to fail and retry

With this in mind I wrote a tool (which can be found at the bottom of this page) to scan internal networks and to automatically change the content length to the correct one if a response is received.
With it, I was able to identify a Prometheus instance which dumped thousands of internal IPs, hostnames, environment configurations.

A couple of limitations prevented straightforward escalation, namely:

- Only ```GET``` requests can be made
- The client does not accept the authority that signed the certificates for internal services, making HTTPS connection to internal hosts impossible

I then reported the vulnerability to the company, making it known I had the intention of continuing testing to try to escalate this further, which I believe would likely have been possible by the sheer amount of internal services available, some of them being debugging instances. Unfortunately the company didn't allow this and patched the vulnerability only an hour later

<details markdown="1">
<summary>Scanner: <code>scanner.py</code></summary>

{% highlight python %}
{% include_relative scanner/scanner.py %}
{% endhighlight %}

</details>
