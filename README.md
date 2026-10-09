# URL Validator

[![Latest Version on Packagist](https://img.shields.io/packagist/v/craftcms/url-validator.svg?style=flat-square)](https://packagist.org/packages/craftcms/url-validator)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/craftcms/url-validator/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/craftcms/url-validator/actions?query=workflow%3Arun-tests+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/craftcms/url-validator.svg?style=flat-square)](https://packagist.org/packages/craftcms/url-validator)

Validate URLs and IP addresses before opening a connection, to guard against [Server-Side Request Forgery (SSRF)](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) and DNS rebinding.

By default, the validator rejects:

- Schemes other than `http` and `https` (blocking `file://`, `ftp://`, `gopher://`, etc.)
- Raw IP literals, hex-encoded hostnames, and well-known cloud-metadata domains (AWS, GCP, Kubernetes, …)
- Hostnames that resolve to a private, reserved, loopback, link-local, CGNAT, or cloud-metadata IP address
- IPv6 addresses that embed or tunnel an IPv4 address (IPv4-mapped, NAT64, 6to4, Teredo, …)

All checks happen *before* any connection is opened, and the validator returns the set of IP addresses the host resolved to so you can pin the eventual connection to them (preventing DNS rebinding between validation and download).

## Installation

Install the package via Composer:

```bash
composer require craftcms/url-validator
```

## Usage

```php
use CraftCms\UrlValidator\UrlValidationException;
use CraftCms\UrlValidator\UrlValidator;

$validator = new UrlValidator();
$url = 'https://example.com/image.jpg';

try {
    // Returns the validated IP addresses the host resolves to.
    $ips = $validator->validate($url);
} catch (UrlValidationException $e) {
    // The URL, or an IP it resolves to, is disallowed.
    echo $e->getMessage();
}
```

Use the resolved IPs to pin the connection (e.g. with cURL’s `CURLOPT_RESOLVE`) so the
hostname can’t be re-resolved to a different, internal address between validation and the request:

```php
$parts = parse_url($url);
$host = $parts['host'];
$port = $parts['port'] ?? ($parts['scheme'] === 'https' ? 443 : 80);

$client = new \GuzzleHttp\Client();
$response = $client->get($url, [
    'curl' => [
        // Pin the hostname/port to the IPs we just validated.
        CURLOPT_RESOLVE => ["$host:$port:" . implode(',', $ips)],
    ],
]);
```

### Validating an IP address directly

```php
$validator = new UrlValidator();

$validator->validateIp('8.8.8.8'); // true
$validator->validateIp('169.254.169.254'); // false (AWS metadata IP)
$validator->validateIp('10.0.0.5'); // false (private range)
```

`validateScheme(string $url): bool` and `validateHostname(string $url): bool` are also exposed
if you need to check those pieces individually.

### Customizing DNS resolution

By default hostnames are resolved against the system DNS. You can pass a custom resolver to the
constructor — useful for testing, or for plugging in a caching/alternate resolver:

```php
$validator = new UrlValidator(fn(string $host): array => [
    // ...resolved IP addresses for $host
]);
```
### Customizing other options

The following options can also be configured by passing an array to the constructor as a second parameter. The following options are customizable:
- `allowedSchemes`
- `disallowedHostnames`
- `disallowedIpv4Addresses`
- `disallowedIpv4Ranges`
- `disallowedIpv6Addresses`
- `ipv4FilterFlags` (the `FILTER_FLAG_IPV4` will always be added automatically)
- `ipv6FilterFlags` (the `FILTER_FLAG_IPV6` will always be added automatically)
- `allowedPrivateHosts` (see [Allowing internal hosts](#allowing-internal-hosts))

See the codebase for the default values and expected types.

```php
// Allow private IP addresses but keep the reserved ranges disallowed
$validator = new UrlValidator(options: ['ipv4FilterFlags' => FILTER_FLAG_NO_RES_RANGE]);
```

### Allowing internal hosts

Private IP addresses (e.g. `10.0.0.0/8`, `192.168.0.0/16`, `fd00::/8`) are rejected by default. If your app needs to reach internal services, for example in local development or between containers in Docker or Kubernetes, list the hostnames that may resolve to private addresses:

```php
$validator = new UrlValidator(options: [
    'allowedPrivateHosts' => [
        'my-api.internal',
        '*.ddev.site',
    ],
]);
```

- An exact hostname matches only that host.
- A leading `*.` wildcard matches any subdomain, e.g. `*.site.testing.local` matches `api.site.testing.local` and `a.b.site.testing.local`, but not `site.testing.local` itself.
- `*` isn’t allowed anywhere else, and a bare `*` isn’t allowed at all. Invalid patterns throw an `InvalidArgumentException`.
- Only the private-range check is relaxed for these hosts. Loopback, link-local, reserved and cloud-metadata addresses, and disallowed hostnames such as `kubernetes.default.svc`, are still rejected.

> [!WARNING]
> - Only list hostnames whose DNS you control. Never list wildcard-DNS services such as `nip.io` or `sslip.io`, which resolve to whatever IP address is in the name.
> - List individual services rather than whole internal domains. Every listed host is reachable by anyone who can make your app send a request to it.
> - Don’t let users edit this list (e.g. through a control panel). Keep it in code or config files.

### Pinning with curl

Validating a URL and then letting curl resolve its hostname again leaves room for DNS rebinding. `curlResolve()` validates the URL and returns a `CURLOPT_RESOLVE` value that pins the hostname and port to the validated IP addresses.

```php
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RESOLVE, $validator->curlResolve($url));
```

### Using with Guzzle

Requires `guzzlehttp/guzzle`. `GuzzleMiddleware` validates and pins every request a Guzzle client sends, including the ones sent while following redirects. A disallowed URL makes the request throw an `UrlValidationException`.

If the client has already been created, you can add the middleware to its handler stack:

```php
GuzzleMiddleware::attach($client, $validator);
```

Otherwise, create the client with the handler stack:

```php
use CraftCms\UrlValidator\GuzzleMiddleware;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;

$stack = HandlerStack::create();
GuzzleMiddleware::push($stack, $validator);
$client = new Client(['handler' => $stack]);
```

> [!NOTE]
> - Pinning only works with Guzzle’s curl handler. The middleware turns the `stream` request option off, because the stream handler would ignore the pin.
> - When requests go through an HTTP proxy, the proxy resolves the hostname itself, so the pin doesn’t apply there. URLs are still validated, but the proxy should enforce its own egress rules.

## Testing

```bash
composer test
```

```bash
composer analyse
```

```bash
composer format
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Security vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Pixel & Tonic](https://github.com/craftcms)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
