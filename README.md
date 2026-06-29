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
- `ipv4FilterFlags` (the `FILTER_FLAG_IPV4` will always be added automatically)
- `ipv6FilterFlags` (the `FILTER_FLAG_IPV6` will always be added automatically)

See the codebase for the default values and expected types.

```php
// Allow private IP addresses but keep the reserved ranges disallowed
$validator = new UrlValidator(options: ['ipv4FilterFlags' => FILTER_FLAG_NO_RES_RANGE]);
```

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
