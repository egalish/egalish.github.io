---
title: Stored XSS in legacy application
parent: Writeups
nav_order: 1
tags: [xss]
---

# Stored XSS in legacy appplication
{: .no_toc }

**Severity:** Medium, CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N)  
**Vulnerability Class:** CWE-918: Server-Side Request Forgery (SSRF)  
**Impact:** Internal network enumeration  

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Summary
A Stored XSS vulnerability was found in an old domain, which would have allowed attackers to launch a phishing campaign trying to exploit users of the modern app

## Vulnerability Details
On a legacy domain (probably used for debugging purposes) the endpoints `/insert` and `/read` were discovered.

The first expected a query parameter named `query`, the value of which would have been displayed on the response wrapped in an `<h1>` tag, along with a numeric id.  
The second expected the parameter `id`, and returned the response to the `/insert?query=` request corresponding to that id.

It was straightforward to escape the `<h1>` tag and inject an XSS payload

## Exploitability
On the surface it seems like this vulnerability has no impact at all, but it is not entirely true.

Since on the modern application the cookies are set with `Domain=.company.com` and `SameSite=lax`, and the old domain in question is a subdomain of `company.com`, if an attacker can convince a user of the modern app to visit a link containing an XSS payload, then they can perform actions on that user's behalf on the main application