# Features

Enumerate vhosts from a list of IP addresses and domain names.

Virtual Hosts are enumerated using the following process:

* Supplied domains are resolved (all IPv4 and IPv6 addresses are added to scope)
* All IP addresses are scanned for HTTP(S) services (using a default port list, see help)
* Query external APIs (rapiddns) if enabled via --apis to find vhosts from IP or subdomains from domain
* For all HTTP services, find vhosts using these techniques :
    * TLS certificate parsing (for hosts with TLS service running)
        * CertCN
        * AltNames
    * HTTP headers parsing (for detected HTTP services)
        * Location header
        * Access-Control-Allow-Origin header
        * Content-Security-Policy header
    * JavaScript redirect (\*.location=) when contains absolute URL
* The whole process is repeated N times (--recursion-depth, default 2) on newfound IP addresses and hostnames. Increasing recursion depth will enumerate more hosts but may go out of scope.


# Install

```
pip3 install -r requirements.txt
```

# Quick usage

targets.txt contains a newline-separated list of hostnames, ip addresses and CIDRS

```
$ cat targets.txt 
accounts.coinbase.com
api.coinbase.com
api.custody.coinbase.com
api.exchange.coinbase.com
api.pro.coinbase.com
api-public.sandbox.pro.coinbase.com
api.wallet.coinbase.com
app.analytics.coinbase.com
assethub-api.coinbase.com
assets.coinbase.com
assets-test.coinbase.com
beta.coinbase.com
billing-systems.coinbase.com
blockchain.wallet.coinbase.com
blog.coinbase.com
braintree-webhooks.coinbase.com
buy.coinbase.com
card.coinbase.com
cloud.coinbase.com
community.coinbase.com
...
```

Simple usage:
```
# ./vhostmap.py -t targets.txt 
################################################################################
# PASS 1
# IP to process: 0
# Hostnames to process: 70
################################################################################
[A] developer.coinbase.com 104.18.7.10
[A] developer.coinbase.com 104.18.6.10
[A] api.coinbase.com 104.18.7.10
[A] api.coinbase.com 104.18.6.10
[A] status.prime.coinbase.com 104.18.12.68
[A] status.prime.coinbase.com 104.18.13.68
[A] assethub-api.coinbase.com 104.18.7.10
[A] assethub-api.coinbase.com 104.18.6.10
[A] published-assets.coinbase.com 13.249.15.64
[A] published-assets.coinbase.com 13.249.15.5
[A] published-assets.coinbase.com 13.249.15.121

[...]

################################################################################
# PASS 2
# IP to process: 129
# Hostnames to process: 0
################################################################################
[HTTPService] 104.18.31.151 http://104.18.31.151:80
[HTTPService] 104.18.15.237 http://104.18.15.237:80
[HTTPService] 104.18.20.159 http://104.18.20.159:80
[HTTPService] 162.159.152.4 http://162.159.152.4:80
[CertCN] https://104.18.105.40:8443 billing-systems.coinbase.com
[CertAltName] https://104.18.105.40:8443 billing-systems.coinbase.com
[HTTPService] 104.18.105.40 https://104.18.105.40:443
[CertCN] https://104.18.105.40:443 billing-systems.coinbase.com
[CertAltName] https://104.18.105.40:443 billing-systems.coinbase.com
[HTTPService] 143.204.226.63 http://143.204.226.63:80
[HTTPService] 104.18.8.157 http://104.18.8.157:80
[HTTPService] 143.204.51.121 http://143.204.51.121:80
[HTTPService] 143.204.51.77 http://143.204.51.77:80
[HTTPService] 13.249.15.5 http://13.249.15.5:80

[...]

RESULTS
=========
104.18.6.10 assets-test.coinbase.com translations.coinbase.com sessions.coinbase.com assets.coinbase.com login.coinbase.com assethub-api.coinbase.com www42.coinbase.com graphql.coinbase.com widget.coinbase.com listing.coinbase.com api.coinbase.com braintree-webhooks.coinbase.com sourcemaps.coinbase.com developer.coinbase.com learn.coinbase.com support-dev.coinbase.com status.coinbase.com images.coinbase.com buy.coinbase.com events-service.coinbase.com www.coinbase.com support.coinbase.com cloud.coinbase.com jobs.coinbase.com taxforms.coinbase.com community.coinbase.com static.coinbase.com prime-brokerage.coinbase.com beta.coinbase.com ws.coinbase.com dev.coinbase.com pay.coinbase.com emails.coinbase.com
2606:4700::6812:60a assets-test.coinbase.com translations.coinbase.com sessions.coinbase.com assets.coinbase.com login.coinbase.com assethub-api.coinbase.com www42.coinbase.com graphql.coinbase.com widget.coinbase.com listing.coinbase.com api.coinbase.com braintree-webhooks.coinbase.com sourcemaps.coinbase.com developer.coinbase.com learn.coinbase.com support-dev.coinbase.com status.coinbase.com images.coinbase.com buy.coinbase.com events-service.coinbase.com www.coinbase.com support.coinbase.com cloud.coinbase.com jobs.coinbase.com taxforms.coinbase.com community.coinbase.com static.coinbase.com prime-brokerage.coinbase.com beta.coinbase.com ws.coinbase.com dev.coinbase.com pay.coinbase.com emails.coinbase.com
104.18.7.10 assets-test.coinbase.com translations.coinbase.com sessions.coinbase.com assets.coinbase.com login.coinbase.com assethub-api.coinbase.com www42.coinbase.com graphql.coinbase.com widget.coinbase.com listing.coinbase.com api.coinbase.com braintree-webhooks.coinbase.com sourcemaps.coinbase.com developer.coinbase.com learn.coinbase.com support-dev.coinbase.com status.coinbase.com images.coinbase.com buy.coinbase.com events-service.coinbase.com www.coinbase.com support.coinbase.com cloud.coinbase.com jobs.coinbase.com taxforms.coinbase.com community.coinbase.com static.coinbase.com prime-brokerage.coinbase.com beta.coinbase.com ws.coinbase.com dev.coinbase.com pay.coinbase.com emails.coinbase.com

[...]
```

Example 2 : 

```
# ./vhostmap.py -t targets.txt -p large --apis -o out
```
- **--apis** : Use external API to find subdomains and virtual hosts (rapiddns)
- **-p large** : Search for web services on a larger port list
- **-o out** : Store results in "out" folder

Output folder contains multiple result files:

* all-hostnames.txt : final hostname list, one by line
* all-ips.txt : final list of all IP address associated with one or more hostnames, one by line
* all-urls.txt : all valid web services found, one by line
* hosts.txt : /etc/hosts format file associating IP addresses with vhosts
* log.txt : tool output
