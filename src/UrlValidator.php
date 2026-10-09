<?php

namespace CraftCms\UrlValidator;

/**
 * Validates URLs and IP addresses against SSRF.
 *
 * This guards against SSRF by rejecting disallowed schemes and hostnames, and any
 * hostname that resolves to a private, reserved, loopback, link-local, or known
 * cloud-metadata IP address — all *before* any connection is opened.
 *
 * @author Pixel & Tonic, Inc. <support@pixelandtonic.com>
 */
class UrlValidator
{
    /**
     * @var callable(string):string[] Resolves a hostname to its IP addresses.
     */
    private $resolver;

    /**
     * @var array|string[] A list of allowed schemes.
     */
    private array $allowedSchemes = ['http', 'https'];

    /**
     * @var array|string[] A list of disallowed hostnames.
     *
     * By default, this is a list of well-known cloud metadata domains which should be rejected.
     * h/t https://gist.github.com/BuffaloWill/fa96693af67e3a3dd3fb
     */
    private array $disallowedHostnames = [
        'kubernetes.default',
        'kubernetes.default.svc',
        'kubernetes.default.svc.cluster.local',
        'metadata',
        'metadata.google.internal',
        'metadata.packet.net',
    ];

    /**
     * @var array|string[] A list of disallowed IPv4 addresses.
     *
     * By default, we want to make sure it isn’t a known cloud metadata IP
     * h/t https://gist.github.com/BuffaloWill/fa96693af67e3a3dd3fb
     */
    private array $disallowedIpv4Addresses = [
        '100.100.100.200', // Alibaba
        '169.254.169.254', // AWS, GCP, DO, Azure, Oracle, OpenStack/RackSpace
        '169.254.170.2', // ECS
        '192.0.0.192', // Oracle
    ];

    /**
     * @var array{0:string,1:int}[] A list of disallowed IPv4 subnets.
     *
     * By default, we block ranges PHP’s NO_PRIV_RANGE/NO_RES_RANGE flags don’t cover.
     */
    private array $disallowedIpv4Ranges = [
        ['100.64.0.0', 10], // CGNAT shared address space (RFC 6598)
        ['192.0.0.0', 24], // IETF protocol assignments (RFC 6890)
        ['198.18.0.0', 15], // benchmarking (RFC 2544)
    ];

    /**
     * @var int The flags to use when validating IPv4 addresses.
     *
     * By default, we only allow publicly-routable IPs (blocks private, loopback, link-local, etc.)
     */
    private int $ipv4FilterFlags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_IPV4;

    /**
     * @var int The flags to use when validating IPv6 addresses.
     *
     * By default, we only allow publicly-routable IPs (blocks loopback, link-local, ULA, etc.)
     */
    private int $ipv6FilterFlags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_IPV6;

    /**
     * @var string[] A list of hostnames that are allowed to resolve to private IP addresses.
     *
     * Each entry is either an exact hostname (`api.internal`) or a leading `*.` wildcard
     * (`*.ddev.site`), which matches any subdomain but not the domain itself.
     * Only the private-range check is relaxed for these hosts. Reserved, loopback, link-local,
     * cloud-metadata and other disallowed addresses and hostnames are still rejected.
     */
    private array $allowedPrivateHosts = [];

    /**
     * @param  callable(string):string[]|null  $resolver  A custom hostname resolver, primarily
     *                                                    useful for testing. Receives a hostname and should return its IP addresses. Defaults to
     *                                                    resolving against the system DNS via [[resolveHostIps()]].
     * @param  array{allowedSchemes?:string[],disallowedHostnames?:string[],disallowedIpv4Addresses?:string[],disallowedIpv4Ranges?:array{0:string,1:int}[],ipv4FilterFlags?:int,ipv6FilterFlags?:int,allowedPrivateHosts?:string[]}|null  $options  Overrides for the default validation rules. Any key that’s omitted falls back to its default. `ipv4FilterFlags`/`ipv6FilterFlags` are combined with `FILTER_FLAG_IPV4`/`FILTER_FLAG_IPV6` respectively, so those don’t need to be included.
     *
     * @throws \InvalidArgumentException if an `allowedPrivateHosts` entry isn’t a valid pattern.
     */
    public function __construct(?callable $resolver = null, ?array $options = null)
    {
        $this->resolver = $resolver ?? fn (string $host): array => $this->resolveHostIps($host);

        if (! empty($options)) {
            $this->allowedSchemes = $options['allowedSchemes'] ?? $this->allowedSchemes;
            $this->disallowedHostnames = $options['disallowedHostnames'] ?? $this->disallowedHostnames;
            $this->disallowedIpv4Addresses = $options['disallowedIpv4Addresses'] ?? $this->disallowedIpv4Addresses;
            $this->disallowedIpv4Ranges = $options['disallowedIpv4Ranges'] ?? $this->disallowedIpv4Ranges;

            if (isset($options['ipv4FilterFlags'])) {
                // if the options come from the user, ensure the ipv4 flag is always set
                $this->ipv4FilterFlags = $options['ipv4FilterFlags'] | FILTER_FLAG_IPV4;
            }

            if (isset($options['ipv6FilterFlags'])) {
                // if the options come from the user, ensure the ipv6 flag is always set
                $this->ipv6FilterFlags = $options['ipv6FilterFlags'] | FILTER_FLAG_IPV6;
            }

            if (isset($options['allowedPrivateHosts'])) {
                $this->allowedPrivateHosts = array_map(
                    fn ($pattern): string => $this->normalizeAllowedPrivateHost($pattern),
                    $options['allowedPrivateHosts'],
                );
            }
        }
    }

    /**
     * Validates a remote URL and resolves it to a list of allowed IP addresses.
     *
     * This guards against SSRF by rejecting disallowed schemes and hostnames, and any
     * hostname that resolves to a private, reserved, loopback, link-local, or known
     * cloud-metadata IP address — all *before* any connection is opened.
     *
     * @return string[] The validated IP addresses the host resolves to.
     *
     * @throws UrlValidationException if the URL, or any IP it resolves to, is disallowed.
     */
    public function validate(string $url): array
    {
        if (! $this->validateScheme($url)) {
            throw new UrlValidationException("$url contains an invalid scheme.");
        }

        if (! $this->validateHostname($url)) {
            throw new UrlValidationException("$url contains an invalid hostname.");
        }

        $host = (string) parse_url($url, PHP_URL_HOST);
        $allowPrivate = $this->isAllowedPrivateHost($host);
        $ips = ($this->resolver)($host);

        if (empty($ips)) {
            throw new UrlValidationException("$url could not be resolved to an IP address.");
        }

        foreach ($ips as $ip) {
            if (! $this->validateIp($ip, $allowPrivate)) {
                throw new UrlValidationException("$url resolves to an invalid IP address.");
            }
        }

        return $ips;
    }

    /**
     * Validates a remote URL and returns a `CURLOPT_RESOLVE` value that pins its hostname and port to the validated IP addresses.
     *
     * @return string[]
     *
     * @throws UrlValidationException if the URL, or any IP it resolves to, is disallowed.
     */
    public function curlResolve(string $url): array
    {
        $ips = $this->validate($url);

        $parts = parse_url($url);
        $host = $parts['host'] ?? '';
        $scheme = strtolower($parts['scheme'] ?? '');

        if ($host === '' || $scheme === '') {
            throw new UrlValidationException("$url could not be pinned to its resolved IP addresses.");
        }

        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

        // IPv6 addresses need to be wrapped in brackets
        $ips = array_map(fn (string $ip): string => str_contains($ip, ':') ? "[$ip]" : $ip, $ips);

        return ["$host:$port:".implode(',', $ips)];
    }

    /**
     * Returns whether a URL’s scheme is allowed (only `http` and `https`).
     */
    public function validateScheme(string $url): bool
    {
        // block Gopher/File/FTP Smuggling
        $scheme = parse_url($url, PHP_URL_SCHEME);

        return in_array(strtolower((string) $scheme), $this->allowedSchemes, true);
    }

    /**
     * Returns whether a URL’s hostname is allowed.
     *
     * Rejects raw IP literals, hex-encoded hostnames, and well-known cloud-metadata domains.
     */
    public function validateHostname(string $url): bool
    {
        // normalize so the metadata-domain checks below can’t be evaded with
        // uppercase letters or a trailing “.” (absolute FQDN form)
        $hostname = rtrim(strtolower((string) parse_url($url, PHP_URL_HOST)), '.');

        // convert hex segments to decimal
        $hostname = implode('.', array_map(function (string $chunk): string {
            if (str_starts_with(strtolower($chunk), '0x')) {
                $octets = str_split(substr($chunk, 2), 2);

                return implode('.', array_map('hexdec', $octets));
            }

            return $chunk;
        }, explode('.', $hostname)));

        // make sure the hostname is alphanumeric and not an IP address
        if (
            ! filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) ||
            filter_var($hostname, FILTER_VALIDATE_IP)
        ) {
            return false;
        }

        if (in_array($hostname, $this->disallowedHostnames, true)) {
            return false;
        }

        return true;
    }

    /**
     * Returns whether an IP address is publicly routable and safe to connect to.
     *
     * Rejects private, reserved, loopback, link-local, CGNAT, and cloud-metadata
     * addresses, as well as IPv6 addresses that embed or tunnel an IPv4 address.
     * Private addresses are allowed when `$allowPrivate` is true.
     */
    public function validateIp(string $ip, bool $allowPrivate = false): bool
    {
        // Parse to the packed (binary) form so checks are done on the canonical
        // address rather than its textual representation — which has many
        // equivalent forms (e.g. uppercase/compressed IPv6) that string
        // comparisons would miss.
        $packed = @inet_pton($ip);

        if ($packed === false) {
            // not a valid IP address
            return false;
        }

        return match (strlen($packed)) {
            4 => $this->validateIpv4($ip, $allowPrivate),
            16 => $this->validateIpv6($ip, $packed, $allowPrivate),
            default => false,
        };
    }

    private function validateIpv4(string $ip, bool $allowPrivate): bool
    {
        if (in_array($ip, $this->disallowedIpv4Addresses, true)) {
            return false;
        }

        foreach ($this->disallowedIpv4Ranges as [$subnet, $bits]) {
            if ($this->ipv4InRange($ip, $subnet, $bits)) {
                return false;
            }
        }

        $flags = $allowPrivate ? $this->ipv4FilterFlags & ~FILTER_FLAG_NO_PRIV_RANGE : $this->ipv4FilterFlags;

        return filter_var($ip, FILTER_VALIDATE_IP, $flags) !== false;
    }

    private function validateIpv6(string $ip, string $packed, bool $allowPrivate): bool
    {
        // Reject any IPv6 address that embeds or tunnels an IPv4 address. We never
        // legitimately need to fetch a file over one, and they’re a common way to
        // smuggle a target past IPv6-only checks (e.g. 64:ff9b::7f00:1 → 127.0.0.1).
        $embeddedPrefixes = [
            str_repeat("\x00", 10)."\xff\xff", // IPv4-mapped ::ffff:0:0/96
            str_repeat("\x00", 12), // IPv4-compatible ::/96 (incl. ::, ::1)
            "\x00\x64\xff\x9b".str_repeat("\x00", 8), // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052)
            "\x20\x02", // 6to4 2002::/16 (RFC 3056)
            "\x20\x01\x00\x00", // Teredo 2001:0000::/32 (RFC 4380)
        ];

        foreach ($embeddedPrefixes as $prefix) {
            if (str_starts_with($packed, $prefix)) {
                return false;
            }
        }

        // Site-local fec0::/10 (deprecated, RFC 3879) — PHP doesn’t flag it reserved
        if (ord($packed[0]) === 0xFE && (ord($packed[1]) & 0xC0) === 0xC0) {
            return false;
        }

        $flags = $allowPrivate ? $this->ipv6FilterFlags & ~FILTER_FLAG_NO_PRIV_RANGE : $this->ipv6FilterFlags;

        return filter_var($ip, FILTER_VALIDATE_IP, $flags) !== false;
    }

    /**
     * Returns whether a hostname is allowed to resolve to private IP addresses.
     */
    private function isAllowedPrivateHost(string $host): bool
    {
        // normalize the same way validateHostname() does
        $host = rtrim(strtolower($host), '.');

        foreach ($this->allowedPrivateHosts as $pattern) {
            if (str_starts_with($pattern, '*.')) {
                // a wildcard matches any subdomain, but not the domain itself
                if (str_ends_with($host, substr($pattern, 1))) {
                    return true;
                }
            } elseif ($host === $pattern) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalizes an allowed private host pattern and makes sure it’s safe to match against.
     *
     * @throws \InvalidArgumentException if the pattern isn’t an exact hostname or a leading `*.` wildcard.
     */
    private function normalizeAllowedPrivateHost(mixed $pattern): string
    {
        if (! is_string($pattern)) {
            throw new \InvalidArgumentException('Allowed private hosts must be strings.');
        }

        $normalized = rtrim(strtolower(trim($pattern)), '.');

        // `*` is only allowed as a whole leading label (e.g. `*.ddev.site`), so that
        // a pattern like `api*` can’t also match `api.attacker.com`
        $name = str_starts_with($normalized, '*.') ? substr($normalized, 2) : $normalized;

        if ($name === '' || str_contains($name, '*')) {
            throw new \InvalidArgumentException("“{$pattern}” isn’t a valid allowed private host.");
        }

        return $normalized;
    }

    /**
     * Returns whether an IPv4 address falls within the given CIDR subnet.
     *
     * @param  int  $bits  The network prefix length (0–32).
     */
    private function ipv4InRange(string $ip, string $subnet, int $bits): bool
    {
        $long = ip2long($ip);
        $base = ip2long($subnet);

        if ($long === false || $base === false) {
            return false;
        }

        $mask = $bits === 0 ? 0 : (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF;

        return (($long & 0xFFFFFFFF) & $mask) === (($base & 0xFFFFFFFF) & $mask);
    }

    /**
     * Resolves a hostname to all of its IPv4 and IPv6 addresses.
     *
     * @return string[]
     */
    protected function resolveHostIps(string $host): array
    {
        $ips = [];

        foreach ([DNS_A, DNS_AAAA] as $type) {
            foreach (@dns_get_record($host, $type) ?: [] as $record) {
                $ip = $record['ip'] ?? $record['ipv6'] ?? null;
                if ($ip !== null) {
                    $ips[] = $ip;
                }
            }
        }

        return array_values(array_unique($ips));
    }
}
