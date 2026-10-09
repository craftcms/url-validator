<?php

declare(strict_types=1);

use CraftCms\UrlValidator\UrlValidationException;
use CraftCms\UrlValidator\UrlValidator;

/**
 * Builds a validator with the given allowed private hosts and a stubbed resolver.
 *
 * @param  string[]  $allowedPrivateHosts
 * @param  string[]  $resolvedIps
 */
function allowlistValidator(array $allowedPrivateHosts, array $resolvedIps): UrlValidator
{
    // Stub DNS resolution so the test never touches the network.
    return new UrlValidator(fn (): array => $resolvedIps, ['allowedPrivateHosts' => $allowedPrivateHosts]);
}

// If you put a hostname on the allowlist, that host is allowed to point at an internal network address (like 10.0.0.5 or 192.168.1.10),
// which would normally be blocked
it('lets allowlisted hosts resolve to private IPs', function (array $patterns, string $url, array $resolvedIps) {
    expect(allowlistValidator($patterns, $resolvedIps)->validate($url))->toBe($resolvedIps);
})->with([
    'exact host, 10/8' => [['api.internal'], 'http://api.internal/', ['10.0.0.5']],
    'exact host, 172.16/12' => [['api.internal'], 'http://api.internal/', ['172.16.5.4']],
    'exact host, 192.168/16' => [['api.internal'], 'http://api.internal/', ['192.168.1.10']],
    'exact host, ula v6' => [['api.internal'], 'http://api.internal/', ['fd12::1']],
    'wildcard, one label' => [['*.svc.cluster.local'], 'http://x.svc.cluster.local/', ['10.0.0.5']],
    'wildcard, two labels' => [['*.svc.cluster.local'], 'http://a.b.svc.cluster.local/', ['10.0.0.5']],
    'host case and trailing dot' => [['api.internal'], 'http://API.Internal./', ['10.0.0.5']],
    'pattern case and trailing dot' => [['API.internal.'], 'http://api.internal/', ['10.0.0.5']],
    'public and private ips' => [['api.internal'], 'http://api.internal/', ['8.8.8.8', '10.0.0.5']],
    'public ip' => [['api.internal'], 'http://api.internal/', ['8.8.8.8']],
]);

// allowlisting never unblocks loopback, link-local, metadata (including IPv6 metadata), CGNAT, other reserved ranges, or IPv4 hidden inside IPv6
it('still rejects disallowed IPs for allowlisted hosts', function (string $ip) {
    expect(fn () => allowlistValidator(['api.internal'], [$ip])->validate('http://api.internal/'))
        ->toThrow(UrlValidationException::class, 'resolves to an invalid IP address');
})->with([
    'loopback' => ['127.0.0.1'],
    'ipv6 loopback' => ['::1'],
    'link-local v4' => ['169.254.1.1'],
    'ipv6 link-local' => ['fe80::1'],
    'aws metadata ip' => ['169.254.169.254'],
    'alibaba metadata ip' => ['100.100.100.200'],
    'oracle metadata ip' => ['192.0.0.192'],
    'aws metadata v6' => ['fd00:ec2::254'],
    'aws metadata v6, other spelling' => ['FD00:0EC2:0:0::254'],
    'gcp metadata v6' => ['fd20:ce::254'],
    'cgnat' => ['100.64.0.1'],
    'protocol assignments' => ['192.0.0.171'],
    'benchmarking range' => ['198.18.0.1'],
    'ipv6 unspecified' => ['::'],
    'ipv4-mapped private' => ['::ffff:10.0.0.1'],
    'nat64 private' => ['64:ff9b::a00:1'],
    '6to4 private' => ['2002:a00:1::'],
    'site-local v6' => ['fec0::1'],
]);

// One bad IP, such as loopback, among otherwise acceptable private IPs fails the whole URL.
it('rejects allowlisted hosts if any of their IPs is disallowed', function () {
    expect(fn () => allowlistValidator(['api.internal'], ['10.0.0.5', '127.0.0.1'])->validate('http://api.internal/'))
        ->toThrow(UrlValidationException::class, 'resolves to an invalid IP address');
});

it('only relaxes the check for hosts that match', function (array $patterns, string $url) {
    expect(fn () => allowlistValidator($patterns, ['10.0.0.5'])->validate($url))
        ->toThrow(UrlValidationException::class, 'resolves to an invalid IP address');
})->with([
    'host not on the list' => [['api.internal'], 'http://other.internal/'],
    'empty list' => [[], 'http://api.internal/'],
    'wildcard apex' => [['*.svc.cluster.local'], 'http://svc.cluster.local/'],
    'wildcard without dot boundary' => [['*.svc.cluster.local'], 'http://evilsvc.cluster.local/'],
    'exact host without dot boundary' => [['api.internal'], 'http://xapi.internal/'],
    'exact host as a prefix' => [['api.internal'], 'http://api.internal.attacker.com/'],
    'exact host as a subdomain' => [['api.internal'], 'http://sub.api.internal/'],
]);

// Some hostnames are always blocked because they're known routes to sensitive internal.
// Listing kubernetes.default.svc, metadata.google.internal or an IP literal doesn't let it through.
it('keeps blocking disallowed hostnames even if allowlisted', function (array $patterns, string $url) {
    expect(fn () => allowlistValidator($patterns, ['10.0.0.5'])->validate($url))
        ->toThrow(UrlValidationException::class, 'contains an invalid hostname');
})->with([
    'k8s domain' => [['kubernetes.default.svc'], 'http://kubernetes.default.svc/'],
    'gce metadata domain' => [['metadata.google.internal'], 'http://metadata.google.internal/'],
    'ip literal' => [['10.0.0.1'], 'http://10.0.0.1/'],
]);

it('rejects invalid patterns', function (mixed $pattern) {
    expect(fn () => new UrlValidator(options: ['allowedPrivateHosts' => [$pattern]]))
        ->toThrow(InvalidArgumentException::class);
})->with([
    'bare wildcard' => ['*'],
    'wildcard without a domain' => ['*.'],
    'trailing wildcard' => ['api*'],
    'wildcard in the middle' => ['a.*.b'],
    'partial leading wildcard' => ['*foo.com'],
    'double wildcard' => ['**.foo'],
    'empty string' => [''],
    'integer' => [123],
    'null' => [null],
]);

it('lets validateIp() allow private IPs', function () {
    $validator = new UrlValidator;

    expect($validator->validateIp('10.0.0.1'))->toBeFalse()
        ->and($validator->validateIp('10.0.0.1', true))->toBeTrue()
        ->and($validator->validateIp('fd12::1', true))->toBeTrue()
        ->and($validator->validateIp('127.0.0.1', true))->toBeFalse()
        ->and($validator->validateIp('169.254.169.254', true))->toBeFalse()
        ->and($validator->validateIp('fd00:ec2::254', true))->toBeFalse();
});
