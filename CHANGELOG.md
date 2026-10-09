# Changelog

## 1.2.0 - 2026-10-09 

- Added `UrlValidator::curlResolve()`.
- Added `GuzzleMiddleware`, which validates and pins every request a Guzzle client sends, including redirects.
- Added the `allowedPrivateHosts` option, which lets specific hostnames resolve to private IP addresses.
- Added the `disallowedIpv6Addresses` option. By default, it blocks the AWS and GCP IPv6 metadata addresses.

## 1.1.0 - 2026-07-06

- Added an `$options` argument to the `UrlValidator` constructor. ([#2](https://github.com/craftcms/url-validator/pull/2))

## 1.0.0 - 2026-06-15

- Initial release
