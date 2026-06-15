<?php

declare(strict_types=1);

use CraftCms\UrlValidator\UrlValidationException;
use CraftCms\UrlValidator\UrlValidator;

/**
 * Tests that URLs are validated before any download happens (SSRF guard):
 * disallowed URLs/IPs throw, allowed ones return their resolved IPs so the download can proceed.
 *
 * @param  string  $url
 * @param  string[]  $resolvedIps  The IPs the host “resolves” to (DNS resolution is stubbed).
 * @param  string|null  $exception  The expected exception message fragment, or null if the URL should validate.
 */
it('validates URLs', function (string $url, array $resolvedIps, ?string $exception) {
    // Stub DNS resolution so the test never touches the network.
    $validator = new UrlValidator(fn (): array => $resolvedIps);

    if ($exception !== null) {
        expect(fn () => $validator->validate($url))
            ->toThrow(UrlValidationException::class, $exception);

        return;
    }

    // Allowed: validation passes and returns the IPs the download gets pinned to.
    expect($validator->validate($url))->toBe($resolvedIps);
})->with([
    // Allowed public hosts resolving to public IPs
    'public ipv4 over http' => ['http://example.com/image.jpg', ['93.184.216.34'], null],
    'public ipv4 over https' => ['https://cdn.example.com/image.png', ['8.8.8.8'], null],
    'public ipv6' => ['https://example.com/image.gif', ['2606:2800:220:1:248:1893:25c8:1946'], null],
    'multiple public ips' => ['https://example.com/image.webp', ['93.184.216.34', '8.8.8.8'], null],
    'public ipv4 + ipv6' => ['https://example.com/image.svg', ['1.1.1.1', '2606:4700:4700::1111'], null],
    // Just outside the CGNAT 100.64.0.0/10 range — still public, must be allowed
    'cgnat boundary below' => ['https://example.com/below.jpg', ['100.63.255.255'], null],
    'cgnat boundary above' => ['https://example.com/above.jpg', ['100.128.0.1'], null],

    // Disallowed schemes (Gopher/File/FTP smuggling)
    'file scheme' => ['file:///etc/passwd', [], 'contains an invalid scheme'],
    'ftp scheme' => ['ftp://example.com/secret.jpg', [], 'contains an invalid scheme'],
    'gopher scheme' => ['gopher://example.com/_data', [], 'contains an invalid scheme'],

    // Disallowed hostnames — raw IP literals
    'ipv4 literal' => ['http://169.254.169.254/latest/meta-data/', [], 'contains an invalid hostname'],
    'ipv6 literal' => ['http://[::1]/', [], 'contains an invalid hostname'],

    // hex-encoded IP (0x7f000001 == 127.0.0.1)
    'hex-encoded ip' => ['http://0x7f000001/', [], 'contains an invalid hostname'],

    // Disallowed hostnames — well-known cloud metadata domains
    'gce metadata domain' => ['http://metadata.google.internal/computeMetadata/v1/', [], 'contains an invalid hostname'],
    'k8s domain' => ['http://kubernetes.default.svc/', [], 'contains an invalid hostname'],

    // Host resolves, but to a disallowed IP (the SSRF case ON_STATS used to catch too late)
    'aws metadata ip' => ['http://evil.example.com/f.jpg', ['169.254.169.254'], 'resolves to an invalid IP address'],
    'alibaba metadata ip' => ['http://evil.example.com/f.jpg', ['100.100.100.200'], 'resolves to an invalid IP address'],
    'oracle metadata ip' => ['http://evil.example.com/f.jpg', ['192.0.0.192'], 'resolves to an invalid IP address'],
    'loopback' => ['http://evil.example.com/f.jpg', ['127.0.0.1'], 'resolves to an invalid IP address'],
    'private 10/8' => ['http://evil.example.com/f.jpg', ['10.0.0.5'], 'resolves to an invalid IP address'],
    'private 172.16/12' => ['http://evil.example.com/f.jpg', ['172.16.5.4'], 'resolves to an invalid IP address'],
    'private 192.168/16' => ['http://evil.example.com/f.jpg', ['192.168.1.10'], 'resolves to an invalid IP address'],
    'link-local v4' => ['http://evil.example.com/f.jpg', ['169.254.1.1'], 'resolves to an invalid IP address'],
    'ipv6 loopback' => ['http://evil.example.com/f.jpg', ['::1'], 'resolves to an invalid IP address'],
    'ipv6 link-local' => ['http://evil.example.com/f.jpg', ['fe80::1'], 'resolves to an invalid IP address'],
    'ipv4-mapped ipv6' => ['http://evil.example.com/f.jpg', ['::ffff:127.0.0.1'], 'resolves to an invalid IP address'],
    'ipv4-compatible ipv6' => ['http://evil.example.com/f.jpg', ['::127.0.0.1'], 'resolves to an invalid IP address'],
    'ipv6 unspecified' => ['http://evil.example.com/f.jpg', ['::'], 'resolves to an invalid IP address'],
    'gcp metadata v6' => ['http://evil.example.com/f.jpg', ['fd20:ce::1'], 'resolves to an invalid IP address'],
    'ula v6' => ['http://evil.example.com/f.jpg', ['fd12:3456:789a:1::1'], 'resolves to an invalid IP address'],
    'site-local v6' => ['http://evil.example.com/f.jpg', ['fec0::1'], 'resolves to an invalid IP address'],
    'teredo v6' => ['http://evil.example.com/f.jpg', ['2001:0:0:0:0:0:0:1'], 'resolves to an invalid IP address'],

    // CGNAT shared address space (100.64.0.0/10, RFC 6598) — not flagged private/reserved by PHP
    'cgnat start' => ['http://evil.example.com/f.jpg', ['100.64.0.1'], 'resolves to an invalid IP address'],
    'cgnat middle' => ['http://evil.example.com/f.jpg', ['100.96.0.50'], 'resolves to an invalid IP address'],
    'cgnat end' => ['http://evil.example.com/f.jpg', ['100.127.255.254'], 'resolves to an invalid IP address'],

    // Other IPv4 ranges PHP doesn’t flag reserved
    'protocol assignments' => ['http://evil.example.com/f.jpg', ['192.0.0.171'], 'resolves to an invalid IP address'], // 192.0.0.0/24
    'benchmarking range' => ['http://evil.example.com/f.jpg', ['198.18.0.1'], 'resolves to an invalid IP address'], // 198.18.0.0/15

    // Embedded/tunneled IPv4 over IPv6 is blocked outright — whether it wraps an
    // internal target or a public one (we never need to fetch over these forms)
    'nat64 metadata' => ['http://evil.example.com/f.jpg', ['64:ff9b::a9fe:a9fe'], 'resolves to an invalid IP address'], // 169.254.169.254
    'nat64 loopback' => ['http://evil.example.com/f.jpg', ['64:ff9b::127.0.0.1'], 'resolves to an invalid IP address'],
    'nat64 uppercase' => ['http://evil.example.com/f.jpg', ['64:FF9B::a9fe:a9fe'], 'resolves to an invalid IP address'], // case-bypass regression
    'nat64 public' => ['http://evil.example.com/f.jpg', ['64:ff9b::8.8.8.8'], 'resolves to an invalid IP address'],
    '6to4 loopback' => ['http://evil.example.com/f.jpg', ['2002:7f00:1::'], 'resolves to an invalid IP address'], // 127.0.0.1
    '6to4 metadata' => ['http://evil.example.com/f.jpg', ['2002:A9FE:A9FE::'], 'resolves to an invalid IP address'], // 169.254.169.254
    '6to4 public' => ['http://evil.example.com/f.jpg', ['2002:0808:0808::'], 'resolves to an invalid IP address'], // 8.8.8.8
    'ipv4-mapped public' => ['http://evil.example.com/f.jpg', ['::ffff:8.8.8.8'], 'resolves to an invalid IP address'],

    // Mixed: a single bad IP among good ones must still be rejected (we validate all)
    'one bad among good' => ['http://evil.example.com/f.jpg', ['8.8.8.8', '10.0.0.1'], 'resolves to an invalid IP address'],

    // Host doesn’t resolve to anything
    'unresolvable host' => ['http://does-not-resolve.example.com/f.jpg', [], 'could not be resolved'],
]);
