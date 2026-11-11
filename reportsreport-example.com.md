# OSINT Intelligence Report

**Target:** example.com
**Status:** partial  ·  **Collectors:** recon, web-check, openosint-actors
**Started:**   ·  **Finished:** 2026-11-10T00:26:55Z

## Findings (102)

### 1. [recon] A records: 104.20.23.154, 172.66.147.243

| Field | Value |
|-------|-------|
| **Subtype** | dns:A record |
| **Confidence** | 100% |
| **Source** | dns.google / dnspython |

#### Structured value

```json
{
  "type": "A",
  "values": [
    "104.20.23.154",
    "172.66.147.243"
  ]
}
```

### 2. [recon] AAAA records: 2606:4700:10::6814:179a, 2606:4700:10::ac42:93f3

| Field | Value |
|-------|-------|
| **Subtype** | dns:AAAA record |
| **Confidence** | 100% |
| **Source** | dns.google / dnspython |

#### Structured value

```json
{
  "type": "AAAA",
  "values": [
    "2606:4700:10::6814:179a",
    "2606:4700:10::ac42:93f3"
  ]
}
```

### 3. [recon] TXT records: "v=spf1 -all", "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"

| Field | Value |
|-------|-------|
| **Subtype** | dns:TXT record |
| **Confidence** | 100% |
| **Source** | dns.google / dnspython |

#### Structured value

```json
{
  "type": "TXT",
  "values": [
    "\"v=spf1 -all\"",
    "\"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9\""
  ]
}
```

### 4. [recon] MX records: 0 .

| Field | Value |
|-------|-------|
| **Subtype** | dns:MX record |
| **Confidence** | 100% |
| **Source** | dns.google / dnspython |

#### Structured value

```json
{
  "type": "MX",
  "values": [
    "0 ."
  ]
}
```

### 5. [recon] NS records: hera.ns.cloudflare.com, elliott.ns.cloudflare.com

| Field | Value |
|-------|-------|
| **Subtype** | dns:NS record |
| **Confidence** | 100% |
| **Source** | dns.google / dnspython |

#### Structured value

```json
{
  "type": "NS",
  "values": [
    "hera.ns.cloudflare.com",
    "elliott.ns.cloudflare.com"
  ]
}
```

### 6. [recon] RDAP registration lookup (truncated): {"objectClassName":"domain","handle":"2336799_DOMAIN_COM-VRSN","ldhName":"EXAMPLE.COM","links":[{"value":"https:\/\/rdap.verisign.com\/com\/v1\/domain\/example.

| Field | Value |
|-------|-------|
| **Subtype** | rdap |
| **Confidence** | 100% |
| **Source** | rdap.org |

#### Structured value

```json
{
  "rdap": "{\"objectClassName\":\"domain\",\"handle\":\"2336799_DOMAIN_COM-VRSN\",\"ldhName\":\"EXAMPLE.COM\",\"links\":[{\"value\":\"https:\\/\\/rdap.verisign.com\\/com\\/v1\\/domain\\/example.com\",\"rel\":\"self\",\"href\":\"https:\\/\\/rdap.verisign.com\\/com\\/v1\\/domain\\/example.com\",\"type\":\"application\\/rdap+json\"}],\"status\":[\"client delete prohibited\",\"client transfer prohibited\",\"client update prohibited\"],\"entities\":[{\"objectClassName\":\"entity\",\"handle\":\"376\",\"roles\":[\"registrar\"],\"publicIds\":[{\"type\":\"IANA Registrar ID\",\"identifier\":\"376\"}],\"vcardArray\":[\"vcard\",[[\"version\",{},\"text\",\"4.0\"],[\"fn\",{},\"text\",\"RESERVED-Internet Assigned Numbers Authority\"]]],\"entities\":[{\"objectClassName\":\"entity\",\"roles\":[\"abuse\"],\"vcardArray\":[\"vcard\",[[\"version\",{},\"text\",\"4.0\"],[\"fn\",{},\"text\",\"\"],[\"tel\",{\"type\":\"voice\"},\"uri\",\"\"],[\"email\",{},\"text\",\"\"]]]}]}],\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"1995-08-14T04:00:00Z\"},{\"eventAction\":\"expiration\",\"eventDate\":\"2027-08-13T04:00:00Z\"},{\"eventAction\":\"last changed\",\"eventDate\":\"2026-08-14T08:01:43Z\"},{\"eventAction\":\"last update of RDAP database\",\"eventDate\":\"2026-11-10T00:27:15Z\"}],\"secureDNS\":{\"delegationSigned\":true,\"dsData\":[{\"keyTag\":2371,\"algorithm\":13,\"digestType\":"
}
```

#### Raw text

```text
{"objectClassName":"domain","handle":"2336799_DOMAIN_COM-VRSN","ldhName":"EXAMPLE.COM","links":[{"value":"https:\/\/rdap.verisign.com\/com\/v1\/domain\/example.com","rel":"self","href":"https:\/\/rdap.verisign.com\/com\/v1\/domain\/example.com","type":"application\/rdap+json"}],"status":["client delete prohibited","client transfer prohibited","client update prohibited"],"entities":[{"objectClassName":"entity","handle":"376","roles":["registrar"],"publicIds":[{"type":"IANA Registrar ID","identifier":"376"}],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]],"entities":[{"objectClassName":"entity","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text",""],["tel",{"type":"voice"},"uri",""],["email",{},"text",""]]]}]}],"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},{"eventAction":"expiration","eventDate":"2027-08-13T04:00:00Z"},{"eventAction":"last changed","eventDate":"2026-08-14T08:01:43Z"},{"eventAction":"last update of RDAP database","eventDate":"2026-11-10T00:27:15Z"}],"secureDNS":{"delegationSigned":true,"dsData":[{"keyTag":2371,"algorithm":13,"digestType":
```

### 7. [recon] IP geolocation/ASN: {"ip":"172.66.147.243","success":true,"type":"IPv4","continent":"North America","continent_code":"NA","country":"United States","country_cod

| Field | Value |
|-------|-------|
| **Subtype** | ipwhois |
| **Confidence** | 80% |
| **Source** | ipwho.is |

#### Structured value

```json
{
  "ip": "172.66.147.243"
}
```

#### Raw text

```text
{"ip":"172.66.147.243","success":true,"type":"IPv4","continent":"North America","continent_code":"NA","country":"United States","country_code":"US","region":"California","region_code":"CA","city":"San Francisco","latitude":37.774926,"longitude":-122.4194208,"is_eu":false,"postal":"94119","calling_code":"1","capital":"Washington D.C.","borders":"CA,MX","flag":{"img":"https://cdn.ipwhois.io/flags/us.svg","emoji":"🇺🇸","emoji_unicode":"U+1F1FA U+1F1F8"},"connection":{"asn":13335,"org":"Cloudflare, Inc.","isp":"Cloudflare, Inc.","domain":"cloudflare.com"},"timezone":{"id":"America/Los_Angeles","abbr":"PST","is_dst":false,"offset":-28800,"utc":"-08:00"},"readme":"https://ipwhois.io/docs"}
```

### 8. [recon] IP geolocation: San Francisco, US | ASN AS13335 Cloudflare, Inc.

| Field | Value |
|-------|-------|
| **Subtype** | ipinfo |
| **Confidence** | 80% |
| **Source** | ipinfo.io |

#### Structured value

```json
{
  "ip": "104.20.23.154",
  "city": "San Francisco",
  "region": "California",
  "country": "US",
  "loc": "37.7621,-122.3971",
  "org": "AS13335 Cloudflare, Inc.",
  "postal": "94107",
  "timezone": "America/Los_Angeles",
  "readme": "https://ipinfo.io/missingauth",
  "anycast": true
}
```

### 9. [recon] No security headers detected.

| Field | Value |
|-------|-------|
| **Subtype** | security_headers |
| **Confidence** | 70% |
| **Source** | https://example.com/ |

#### Structured value

```json
{
  "headers": {}
}
```

### 10. [recon] title: Example Domain

| Field | Value |
|-------|-------|
| **Subtype** | html_fingerprint |
| **Confidence** | 60% |
| **Source** | https://example.com |

#### Structured value

```json
{
  "title": "Example Domain",
  "meta_description": "",
  "canonical": "",
  "og": "",
  "tech": []
}
```

### 11. [web-check] DNS record lookup: ['104.20.23.154', '172.66.147.243']

| Field | Value |
|-------|-------|
| **Subtype** | dns:A |
| **Confidence** | 100% |
| **Source** | http://127.0.0.1:3005/api/dns |

#### Structured value

```json
{
  "check": "A",
  "result": [
    "104.20.23.154",
    "172.66.147.243"
  ]
}
```

### 12. [web-check] DNS record lookup: ['2606:4700:10::ac42:93f3', '2606:4700:10::6814:179a']

| Field | Value |
|-------|-------|
| **Subtype** | dns:AAAA |
| **Confidence** | 100% |
| **Source** | http://127.0.0.1:3005/api/dns |

#### Structured value

```json
{
  "check": "AAAA",
  "result": [
    "2606:4700:10::ac42:93f3",
    "2606:4700:10::6814:179a"
  ]
}
```

### 13. [web-check] DNS record lookup: [{'exchange': '', 'priority': 0}]

| Field | Value |
|-------|-------|
| **Subtype** | dns:MX |
| **Confidence** | 100% |
| **Source** | http://127.0.0.1:3005/api/dns |

#### Structured value

```json
{
  "check": "MX",
  "result": [
    {
      "exchange": "",
      "priority": 0
    }
  ]
}
```

### 14. [web-check] DNS record lookup: [['v=spf1 -all'], ['_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9']]

| Field | Value |
|-------|-------|
| **Subtype** | dns:TXT |
| **Confidence** | 100% |
| **Source** | http://127.0.0.1:3005/api/dns |

#### Structured value

```json
{
  "check": "TXT",
  "result": [
    [
      "v=spf1 -all"
    ],
    [
      "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"
    ]
  ]
}
```

### 15. [web-check] DNS record lookup: ['elliott.ns.cloudflare.com', 'hera.ns.cloudflare.com']

| Field | Value |
|-------|-------|
| **Subtype** | dns:NS |
| **Confidence** | 100% |
| **Source** | http://127.0.0.1:3005/api/dns |

#### Structured value

```json
{
  "check": "NS",
  "result": [
    "elliott.ns.cloudflare.com",
    "hera.ns.cloudflare.com"
  ]
}
```

### 16. [web-check] DNS record lookup: []

| Field | Value |
|-------|-------|
| **Subtype** | dns:CNAME |
| **Confidence** | 100% |
| **Source** | http://127.0.0.1:3005/api/dns |

#### Structured value

```json
{
  "check": "CNAME",
  "result": []
}
```

### 17. [web-check] DNS record lookup: {'nsname': 'elliott.ns.cloudflare.com', 'hostmaster': 'dns.cloudflare.com', 'serial': 2418004112, 'refresh': 10000, 'retry': 2400, 'expire': 604800, 'minttl': 1

| Field | Value |
|-------|-------|
| **Subtype** | dns:SOA |
| **Confidence** | 100% |
| **Source** | http://127.0.0.1:3005/api/dns |

#### Structured value

```json
{
  "check": "SOA",
  "result": {
    "nsname": "elliott.ns.cloudflare.com",
    "hostmaster": "dns.cloudflare.com",
    "serial": 2418004112,
    "refresh": 10000,
    "retry": 2400,
    "expire": 604800,
    "minttl": 1800
  }
}
```

### 18. [web-check] DNS record lookup: []

| Field | Value |
|-------|-------|
| **Subtype** | dns:SRV |
| **Confidence** | 100% |
| **Source** | http://127.0.0.1:3005/api/dns |

#### Structured value

```json
{
  "check": "SRV",
  "result": []
}
```

### 19. [web-check] DNS record lookup: []

| Field | Value |
|-------|-------|
| **Subtype** | dns:PTR |
| **Confidence** | 100% |
| **Source** | http://127.0.0.1:3005/api/dns |

#### Structured value

```json
{
  "check": "PTR",
  "result": []
}
```

### 20. [web-check] DNSSEC validation status: {'isFound': True, 'answer': [{'name': 'example.com.', 'type': 48, 'TTL': 3600, 'data': '256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJk

| Field | Value |
|-------|-------|
| **Subtype** | dnssec:DNSKEY |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/dnssec |

#### Structured value

```json
{
  "check": "DNSKEY",
  "result": {
    "isFound": true,
    "answer": [
      {
        "name": "example.com.",
        "type": 48,
        "TTL": 3600,
        "data": "256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA=="
      },
      {
        "name": "example.com.",
        "type": 48,
        "TTL": 3600,
        "data": "256 3 13 MjyZielP0GqniI1+j+wAG/3t0ImDDIlj1CxR0oobkZQHSKH2Fqx6tm2NcYu57POJ83SzCWLkqIjZHS1mh5wbaw=="
      },
      {
        "name": "example.com.",
        "type": 48,
        "TTL": 3600,
        "data": "256 3 13 kxipjoIbNZDsWqEKaYaGq6fM/XThrRp1ue6AV9R/n3eWxpGCeCWJb47PEEEj/Q6VAYFW/7UFo5mXoZfxKYZa3A=="
      },
      {
        "name": "example.com.",
        "type": 48,
        "TTL": 3600,
        "data": "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
      }
    ],
    "response": [
      {
        "name": "example.com.",
        "type": 48,
        "TTL": 3600,
        "data": "256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA=="
      },
      {
        "name": "example.com.",
        "type": 48,
        "TTL": 3600,
        "data": "256 3 13 MjyZielP0GqniI1+j+wAG/3t0ImDDIlj1CxR0oobkZQHSKH2Fqx6tm2NcYu57POJ83SzCWLkqIjZHS1mh5wbaw=="
      },
      {
        "name": "example.com.",
        "type": 48,
        "TTL": 3600,
        "data": "256 3 13 kxipjoIbNZDsWqEKaYaGq6fM/XThrRp1ue6AV9R/n3eWxpGCeCWJb47PEEEj/Q6VAYFW/7UFo5mXoZfxKYZa3A=="
      },
      {
        "name": "example.com.",
        "type": 48,
        "TTL": 3600,
        "data": "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
      }
    ]
  }
}
```

### 21. [web-check] DNSSEC validation status: {'isFound': True, 'answer': [{'name': 'example.com.', 'type': 43, 'TTL': 21600, 'data': '2371 13 2 C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D2

| Field | Value |
|-------|-------|
| **Subtype** | dnssec:DS |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/dnssec |

#### Structured value

```json
{
  "check": "DS",
  "result": {
    "isFound": true,
    "answer": [
      {
        "name": "example.com.",
        "type": 43,
        "TTL": 21600,
        "data": "2371 13 2 C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A"
      }
    ],
    "response": [
      {
        "name": "example.com.",
        "type": 43,
        "TTL": 21600,
        "data": "2371 13 2 C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A"
      }
    ]
  }
}
```

### 22. [web-check] DNSSEC validation status: {'isFound': True, 'answer': None, 'response': {'Status': 0, 'TC': False, 'RD': True, 'RA': True, 'AD': True, 'CD': False, 'Question': [{'name': 'example.com.', 

| Field | Value |
|-------|-------|
| **Subtype** | dnssec:RRSIG |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/dnssec |

#### Structured value

```json
{
  "check": "RRSIG",
  "result": {
    "isFound": true,
    "answer": null,
    "response": {
      "Status": 0,
      "TC": false,
      "RD": true,
      "RA": true,
      "AD": true,
      "CD": false,
      "Question": [
        {
          "name": "example.com.",
          "type": 1
        }
      ],
      "Answer": [
        {
          "name": "example.com.",
          "type": 1,
          "TTL": 300,
          "data": "104.20.23.154"
        },
        {
          "name": "example.com.",
          "type": 1,
          "TTL": 300,
          "data": "172.66.147.243"
        }
      ],
      "Comment": "Response from 108.162.192.162."
    }
  }
}
```

### 23. [web-check] DNS server identification: domain=example.com

| Field | Value |
|-------|-------|
| **Subtype** | dns_server |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/dns-server |

#### Structured value

```json
{
  "check": "domain",
  "value": "example.com"
}
```

### 24. [web-check] DNS server identification: zone=example.com

| Field | Value |
|-------|-------|
| **Subtype** | dns_server |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/dns-server |

#### Structured value

```json
{
  "check": "zone",
  "value": "example.com"
}
```

### 25. [web-check] DNS server identification: [{'address': '172.64.35.228', 'hostname': 'elliott.ns.cloudflare.com'}, {'address': '172.64.32.162', 'hostname': 'hera.ns.cloudflare.com'}]

| Field | Value |
|-------|-------|
| **Subtype** | dns_server:dns |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/dns-server |

#### Structured value

```json
{
  "check": "dns",
  "result": [
    {
      "address": "172.64.35.228",
      "hostname": "elliott.ns.cloudflare.com"
    },
    {
      "address": "172.64.32.162",
      "hostname": "hera.ns.cloudflare.com"
    }
  ]
}
```

### 26. [web-check] Domain registration data: domain=EXAMPLE.COM

| Field | Value |
|-------|-------|
| **Subtype** | whois |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "domain",
  "value": "EXAMPLE.COM"
}
```

### 27. [web-check] Domain registration data: registrar=RESERVED-Internet Assigned Numbers Authority

| Field | Value |
|-------|-------|
| **Subtype** | whois |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "registrar",
  "value": "RESERVED-Internet Assigned Numbers Authority"
}
```

### 28. [web-check] Domain registration data: registrarUrl=http://res-dom.iana.org

| Field | Value |
|-------|-------|
| **Subtype** | whois |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "registrarUrl",
  "value": "http://res-dom.iana.org"
}
```

### 29. [web-check] Domain registration data: registrarIanaId=376

| Field | Value |
|-------|-------|
| **Subtype** | whois |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "registrarIanaId",
  "value": "376"
}
```

### 30. [web-check] Domain registration data: registrarWhoisServer=whois.iana.org

| Field | Value |
|-------|-------|
| **Subtype** | whois |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "registrarWhoisServer",
  "value": "whois.iana.org"
}
```

### 31. [web-check] Domain registration data: registryDomainId=2336799_DOMAIN_COM-VRSN

| Field | Value |
|-------|-------|
| **Subtype** | whois |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "registryDomainId",
  "value": "2336799_DOMAIN_COM-VRSN"
}
```

### 32. [web-check] Domain registration data: created=1995-08-14T04:00:00.000Z

| Field | Value |
|-------|-------|
| **Subtype** | whois |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "created",
  "value": "1995-08-14T04:00:00.000Z"
}
```

### 33. [web-check] Domain registration data: updated=2026-08-14T08:01:43.000Z

| Field | Value |
|-------|-------|
| **Subtype** | whois |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "updated",
  "value": "2026-08-14T08:01:43.000Z"
}
```

### 34. [web-check] Domain registration data: expires=2027-08-13T04:00:00.000Z

| Field | Value |
|-------|-------|
| **Subtype** | whois |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "expires",
  "value": "2027-08-13T04:00:00.000Z"
}
```

### 35. [web-check] Domain registration data: ['elliott.ns.cloudflare.com', 'hera.ns.cloudflare.com']

| Field | Value |
|-------|-------|
| **Subtype** | whois:nameservers |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "nameservers",
  "result": [
    "elliott.ns.cloudflare.com",
    "hera.ns.cloudflare.com"
  ]
}
```

### 36. [web-check] Domain registration data: ['clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited', 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 'clientUpdate

| Field | Value |
|-------|-------|
| **Subtype** | whois:status |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "status",
  "result": [
    "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
    "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
    "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited"
  ]
}
```

### 37. [web-check] Domain registration data: dnssec=signedDelegation

| Field | Value |
|-------|-------|
| **Subtype** | whois |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/whois |

#### Structured value

```json
{
  "check": "dnssec",
  "value": "signedDelegation"
}
```

### 38. [web-check] Passive subdomain enumeration: domain=example.com

| Field | Value |
|-------|-------|
| **Subtype** | subdomains |
| **Confidence** | 70% |
| **Source** | http://127.0.0.1:3005/api/subdomains |

#### Structured value

```json
{
  "check": "domain",
  "value": "example.com"
}
```

### 39. [web-check] Passive subdomain enumeration: count=2

| Field | Value |
|-------|-------|
| **Subtype** | subdomains |
| **Confidence** | 70% |
| **Source** | http://127.0.0.1:3005/api/subdomains |

#### Structured value

```json
{
  "check": "count",
  "value": 2
}
```

### 40. [web-check] Passive subdomain enumeration: truncated=False

| Field | Value |
|-------|-------|
| **Subtype** | subdomains |
| **Confidence** | 70% |
| **Source** | http://127.0.0.1:3005/api/subdomains |

#### Structured value

```json
{
  "check": "truncated",
  "value": false
}
```

### 41. [web-check] Passive subdomain enumeration: ['emudhra-lab.example.com', 'www.example.com']

| Field | Value |
|-------|-------|
| **Subtype** | subdomains:subdomains |
| **Confidence** | 70% |
| **Source** | http://127.0.0.1:3005/api/subdomains |

#### Structured value

```json
{
  "check": "subdomains",
  "result": [
    "emudhra-lab.example.com",
    "www.example.com"
  ]
}
```

### 42. [web-check] Passive subdomain enumeration: source=certSpotter

| Field | Value |
|-------|-------|
| **Subtype** | subdomains |
| **Confidence** | 70% |
| **Source** | http://127.0.0.1:3005/api/subdomains |

#### Structured value

```json
{
  "check": "source",
  "value": "certSpotter"
}
```

### 43. [web-check] Technology fingerprinting: skipped (Could not find Chromium (rev. 1095492). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npm install`) or
 2. your cache path is incorrectly configured (which is: /home/bigdaddy/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.)

| Field | Value |
|-------|-------|
| **Subtype** | tech_stack |
| **Confidence** | 0% |
| **Source** | http://127.0.0.1:3005/api/tech-stack |

#### Structured value

```json
{
  "skipped": "Could not find Chromium (rev. 1095492). This can occur if either\n 1. you did not perform an installation before running the script (e.g. `npm install`) or\n 2. your cache path is incorrectly configured (which is: /home/bigdaddy/.cache/puppeteer).\nFor (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration."
}
```

### 44. [web-check] TLS connection details: protocol=TLSv1.3

| Field | Value |
|-------|-------|
| **Subtype** | tls_connection |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/tls-connection |

#### Structured value

```json
{
  "check": "protocol",
  "value": "TLSv1.3"
}
```

### 45. [web-check] TLS connection details: {'name': 'TLS_AES_256_GCM_SHA384', 'standardName': 'TLS_AES_256_GCM_SHA384', 'version': 'TLSv1.3'}

| Field | Value |
|-------|-------|
| **Subtype** | tls_connection:cipher |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/tls-connection |

#### Structured value

```json
{
  "check": "cipher",
  "result": {
    "name": "TLS_AES_256_GCM_SHA384",
    "standardName": "TLS_AES_256_GCM_SHA384",
    "version": "TLSv1.3"
  }
}
```

### 46. [web-check] TLS connection details: alpnProtocol=h2

| Field | Value |
|-------|-------|
| **Subtype** | tls_connection |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/tls-connection |

#### Structured value

```json
{
  "check": "alpnProtocol",
  "value": "h2"
}
```

### 47. [web-check] TLS connection details: sessionResumption=True

| Field | Value |
|-------|-------|
| **Subtype** | tls_connection |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/tls-connection |

#### Structured value

```json
{
  "check": "sessionResumption",
  "value": true
}
```

### 48. [web-check] TLS connection details: forwardSecrecy=True

| Field | Value |
|-------|-------|
| **Subtype** | tls_connection |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/tls-connection |

#### Structured value

```json
{
  "check": "forwardSecrecy",
  "value": true
}
```

### 49. [web-check] TLS connection details: authorized=True

| Field | Value |
|-------|-------|
| **Subtype** | tls_connection |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/tls-connection |

#### Structured value

```json
{
  "check": "authorized",
  "value": true
}
```

### 50. [web-check] TLS connection details: authError=None

| Field | Value |
|-------|-------|
| **Subtype** | tls_connection |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/tls-connection |

#### Structured value

```json
{
  "check": "authError",
  "value": null
}
```

### 51. [web-check] TLS connection details: {'type': None, 'name': None, 'size': None}

| Field | Value |
|-------|-------|
| **Subtype** | tls_connection:ephemeralKey |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/tls-connection |

#### Structured value

```json
{
  "check": "ephemeralKey",
  "result": {
    "type": null,
    "name": null,
    "size": null
  }
}
```

### 52. [web-check] TLS connection details: ocspStapled=True

| Field | Value |
|-------|-------|
| **Subtype** | tls_connection |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/tls-connection |

#### Structured value

```json
{
  "check": "ocspStapled",
  "value": true
}
```

### 53. [web-check] TLS connection details: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']

| Field | Value |
|-------|-------|
| **Subtype** | tls_connection:versions |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/tls-connection |

#### Structured value

```json
{
  "check": "versions",
  "result": [
    "TLSv1",
    "TLSv1.1",
    "TLSv1.2",
    "TLSv1.3"
  ]
}
```

### 54. [web-check] SSL Labs grade: skipped (SSL Labs: Hostname blacklisted)

| Field | Value |
|-------|-------|
| **Subtype** | tls_labs |
| **Confidence** | 0% |
| **Source** | http://127.0.0.1:3005/api/tls-labs |

#### Structured value

```json
{
  "skipped": "SSL Labs: Hostname blacklisted"
}
```

### 55. [web-check] HSTS policy: message=Site does not serve any HSTS headers.

| Field | Value |
|-------|-------|
| **Subtype** | hsts |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/hsts |

#### Structured value

```json
{
  "check": "message",
  "value": "Site does not serve any HSTS headers."
}
```

### 56. [web-check] HSTS policy: compatible=False

| Field | Value |
|-------|-------|
| **Subtype** | hsts |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/hsts |

#### Structured value

```json
{
  "check": "compatible",
  "value": false
}
```

### 57. [web-check] HSTS policy: hstsHeader=None

| Field | Value |
|-------|-------|
| **Subtype** | hsts |
| **Confidence** | 90% |
| **Source** | http://127.0.0.1:3005/api/hsts |

#### Structured value

```json
{
  "check": "hstsHeader",
  "value": null
}
```

### 58. [web-check] HTTP response headers: age=7756

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "age",
  "value": "7756"
}
```

### 59. [web-check] HTTP response headers: allow=GET, HEAD

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "allow",
  "value": "GET, HEAD"
}
```

### 60. [web-check] HTTP response headers: alt-svc=h3=":443"; ma=86400

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "alt-svc",
  "value": "h3=\":443\"; ma=86400"
}
```

### 61. [web-check] HTTP response headers: cf-cache-status=HIT

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "cf-cache-status",
  "value": "HIT"
}
```

### 62. [web-check] HTTP response headers: cf-ray=a580ef9c0b2be1d2-ATL

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "cf-ray",
  "value": "a580ef9c0b2be1d2-ATL"
}
```

### 63. [web-check] HTTP response headers: connection=keep-alive

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "connection",
  "value": "keep-alive"
}
```

### 64. [web-check] HTTP response headers: content-encoding=br

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "content-encoding",
  "value": "br"
}
```

### 65. [web-check] HTTP response headers: content-type=text/html; charset=utf-8

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "content-type",
  "value": "text/html; charset=utf-8"
}
```

### 66. [web-check] HTTP response headers: date=Tue, 10 Nov 2026 00:28:14 GMT

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "date",
  "value": "Tue, 10 Nov 2026 00:28:14 GMT"
}
```

### 67. [web-check] HTTP response headers: last-modified=Thu, 05 Nov 2026 21:17:41 GMT

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "last-modified",
  "value": "Thu, 05 Nov 2026 21:17:41 GMT"
}
```

### 68. [web-check] HTTP response headers: server=cloudflare

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "server",
  "value": "cloudflare"
}
```

### 69. [web-check] HTTP response headers: transfer-encoding=chunked

| Field | Value |
|-------|-------|
| **Subtype** | http_headers |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/headers |

#### Structured value

```json
{
  "check": "transfer-encoding",
  "value": "chunked"
}
```

### 70. [web-check] Cookie security attributes: []

| Field | Value |
|-------|-------|
| **Subtype** | cookies:headerCookies |
| **Confidence** | 60% |
| **Source** | http://127.0.0.1:3005/api/cookies |

#### Structured value

```json
{
  "check": "headerCookies",
  "result": []
}
```

### 71. [web-check] Cookie security attributes: []

| Field | Value |
|-------|-------|
| **Subtype** | cookies:clientCookies |
| **Confidence** | 60% |
| **Source** | http://127.0.0.1:3005/api/cookies |

#### Structured value

```json
{
  "check": "clientCookies",
  "result": []
}
```

### 72. [web-check] robots.txt inspection: skipped (No robots.txt file present on this host)

| Field | Value |
|-------|-------|
| **Subtype** | robots_txt |
| **Confidence** | 0% |
| **Source** | http://127.0.0.1:3005/api/robots-txt |

#### Structured value

```json
{
  "skipped": "No robots.txt file present on this host"
}
```

### 73. [web-check] security.txt discovery: isPresent=False

| Field | Value |
|-------|-------|
| **Subtype** | security_txt |
| **Confidence** | 70% |
| **Source** | http://127.0.0.1:3005/api/security-txt |

#### Structured value

```json
{
  "check": "isPresent",
  "value": false
}
```

### 74. [web-check] Mixed content detection: url=https://example.com/

| Field | Value |
|-------|-------|
| **Subtype** | mixed_content |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/mixed-content |

#### Structured value

```json
{
  "check": "url",
  "value": "https://example.com/"
}
```

### 75. [web-check] Mixed content detection: upgradeInsecureRequests=False

| Field | Value |
|-------|-------|
| **Subtype** | mixed_content |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/mixed-content |

#### Structured value

```json
{
  "check": "upgradeInsecureRequests",
  "value": false
}
```

### 76. [web-check] Mixed content detection: integrityPolicy=False

| Field | Value |
|-------|-------|
| **Subtype** | mixed_content |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/mixed-content |

#### Structured value

```json
{
  "check": "integrityPolicy",
  "value": false
}
```

### 77. [web-check] Mixed content detection: []

| Field | Value |
|-------|-------|
| **Subtype** | mixed_content:active |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/mixed-content |

#### Structured value

```json
{
  "check": "active",
  "result": []
}
```

### 78. [web-check] Mixed content detection: []

| Field | Value |
|-------|-------|
| **Subtype** | mixed_content:passive |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/mixed-content |

#### Structured value

```json
{
  "check": "passive",
  "result": []
}
```

### 79. [web-check] Mixed content detection: []

| Field | Value |
|-------|-------|
| **Subtype** | mixed_content:forms |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/mixed-content |

#### Structured value

```json
{
  "check": "forms",
  "result": []
}
```

### 80. [web-check] Mixed content detection: thirdPartyScripts=0

| Field | Value |
|-------|-------|
| **Subtype** | mixed_content |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/mixed-content |

#### Structured value

```json
{
  "check": "thirdPartyScripts",
  "value": 0
}
```

### 81. [web-check] Mixed content detection: {'versioned': [], 'unversioned': []}

| Field | Value |
|-------|-------|
| **Subtype** | mixed_content:missingIntegrity |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/mixed-content |

#### Structured value

```json
{
  "check": "missingIntegrity",
  "result": {
    "versioned": [],
    "unversioned": []
  }
}
```

### 82. [web-check] Mixed content detection: []

| Field | Value |
|-------|-------|
| **Subtype** | mixed_content:missingCrossorigin |
| **Confidence** | 80% |
| **Source** | http://127.0.0.1:3005/api/mixed-content |

#### Structured value

```json
{
  "check": "missingCrossorigin",
  "result": []
}
```

### 83. [web-check] Page quality score: skipped (Quality check requires GOOGLE_CLOUD_API_KEY to be set)

| Field | Value |
|-------|-------|
| **Subtype** | quality |
| **Confidence** | 0% |
| **Source** | http://127.0.0.1:3005/api/quality |

#### Structured value

```json
{
  "skipped": "Quality check requires GOOGLE_CLOUD_API_KEY to be set"
}
```

### 84. [web-check] Physical server location: ip=104.20.23.154

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "ip",
  "value": "104.20.23.154"
}
```

### 85. [web-check] Physical server location: city=Toronto

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "city",
  "value": "Toronto"
}
```

### 86. [web-check] Physical server location: region=Ontario

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "region",
  "value": "Ontario"
}
```

### 87. [web-check] Physical server location: country_name=Canada

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "country_name",
  "value": "Canada"
}
```

### 88. [web-check] Physical server location: country_code=CA

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "country_code",
  "value": "CA"
}
```

### 89. [web-check] Physical server location: region_code=ON

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "region_code",
  "value": "ON"
}
```

### 90. [web-check] Physical server location: postal=M5A

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "postal",
  "value": "M5A"
}
```

### 91. [web-check] Physical server location: latitude=43.6532

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "latitude",
  "value": 43.6532
}
```

### 92. [web-check] Physical server location: longitude=-79.3832

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "longitude",
  "value": -79.3832
}
```

### 93. [web-check] Physical server location: org=Cloudflare, Inc.

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "org",
  "value": "Cloudflare, Inc."
}
```

### 94. [web-check] Physical server location: asn=13335

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "asn",
  "value": 13335
}
```

### 95. [web-check] Physical server location: timezone=America/Toronto

| Field | Value |
|-------|-------|
| **Subtype** | location |
| **Confidence** | 50% |
| **Source** | http://127.0.0.1:3005/api/location |

#### Structured value

```json
{
  "check": "timezone",
  "value": "America/Toronto"
}
```

### 96. [openosint-actors] Domain-recon results: {'id': 'ftGimgRrjfIaT323r', 'name': None, 'accessed_at': '2026-11-09 23:36:24.340719+00:00', 'created_at': '2026-11-09 23:36:24.336042+00:00', 'modified_at': '2026-11-09 23:36:24.340719+00:00', 'item_

| Field | Value |
|-------|-------|
| **Subtype** | domain-recon |
| **Confidence** | 80% |
| **Source** | OpenOSINT domain-recon |

#### Structured value

```json
{
  "results": {
    "id": "ftGimgRrjfIaT323r",
    "name": null,
    "accessed_at": "2026-11-09 23:36:24.340719+00:00",
    "created_at": "2026-11-09 23:36:24.336042+00:00",
    "modified_at": "2026-11-09 23:36:24.340719+00:00",
    "item_count": 1
  }
}
```

### 97. [openosint-actors] Handle @username resolved: anonymous

| Field | Value |
|-------|-------|
| **Subtype** | username-recon |
| **Confidence** | 70% |
| **Source** | OpenOSINT username-recon |

#### Structured value

```json
{
  "handle": "username",
  "info": "anonymous"
}
```

### 98. [openosint-actors] Handle @sitesScanned resolved: 0

| Field | Value |
|-------|-------|
| **Subtype** | username-recon |
| **Confidence** | 70% |
| **Source** | OpenOSINT username-recon |

#### Structured value

```json
{
  "handle": "sitesScanned",
  "info": 0
}
```

### 99. [openosint-actors] Handle @accountsFound resolved: 0

| Field | Value |
|-------|-------|
| **Subtype** | username-recon |
| **Confidence** | 70% |
| **Source** | OpenOSINT username-recon |

#### Structured value

```json
{
  "handle": "accountsFound",
  "info": 0
}
```

### 100. [openosint-actors] Handle @sitesSkipped resolved: 0

| Field | Value |
|-------|-------|
| **Subtype** | username-recon |
| **Confidence** | 70% |
| **Source** | OpenOSINT username-recon |

#### Structured value

```json
{
  "handle": "sitesSkipped",
  "info": 0
}
```

### 101. [openosint-actors] Handle @checkedAt resolved: 2026-11-10T00:26:54.198609+00:00

| Field | Value |
|-------|-------|
| **Subtype** | username-recon |
| **Confidence** | 70% |
| **Source** | OpenOSINT username-recon |

#### Structured value

```json
{
  "handle": "checkedAt",
  "info": "2026-11-10T00:26:54.198609+00:00"
}
```

### 102. [openosint-actors] News results: {'query': 'example.com', 'articlesFound': 0, 'checkedAt': '2026-11-10T00:26:55.185020+00:00'}

| Field | Value |
|-------|-------|
| **Subtype** | news-monitor |
| **Confidence** | 60% |
| **Source** | OpenOSINT news-monitor |

#### Structured value

```json
{
  "results": {
    "query": "example.com",
    "articlesFound": 0,
    "checkedAt": "2026-11-10T00:26:55.185020+00:00"
  }
}
```

