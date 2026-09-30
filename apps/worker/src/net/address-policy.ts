import { BlockList, isIP } from 'node:net';

/**
 * Where the worker may never connect (spec §8): private, loopback, link-local, cloud metadata,
 * and every other range that isn't the public internet. Links posted in Discord are attacker
 * input, so following one must never reach our own network.
 */
const blocked = new BlockList();

const IPV4_RANGES: [string, number][] = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, including cloud metadata at 169.254.169.254
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // documentation
  ['192.88.99.0', 24], // 6to4 relay
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // documentation
  ['203.0.113.0', 24], // documentation
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, including broadcast
];

const IPV6_RANGES: [string, number][] = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['64:ff9b:1::', 48], // local NAT64
  ['100::', 64], // discard
  ['2001::', 23], // IETF protocol assignments
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4, can wrap any IPv4 address
  ['fc00::', 7], // unique local, including AWS metadata at fd00:ec2::254
  ['fe80::', 10], // link-local
  ['ff00::', 8], // multicast
];

for (const [address, prefix] of IPV4_RANGES) blocked.addSubnet(address, prefix, 'ipv4');
for (const [address, prefix] of IPV6_RANGES) blocked.addSubnet(address, prefix, 'ipv6');

/** IPv4 wrapped in IPv6 (::ffff:a.b.c.d, NAT64 64:ff9b::/96) is judged by the IPv4 inside. */
function embeddedIpv4(address: string): string | null {
  const lower = address.toLowerCase();
  const dotted = /^(?:::ffff:|64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (dotted) return dotted[1]!;
  const hex = /^(?:::ffff:|64:ff9b::)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);
  if (hex) {
    const high = parseInt(hex[1]!, 16);
    const low = parseInt(hex[2]!, 16);
    return [high >> 8, high & 255, low >> 8, low & 255].join('.');
  }
  return null;
}

/** True for any address the worker must not connect to. Anything unparseable is blocked. */
export function isBlockedAddress(address: string): boolean {
  const bare = address.replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  const version = isIP(bare);
  if (version === 4) return blocked.check(bare, 'ipv4');
  if (version === 6) {
    const inner = embeddedIpv4(bare);
    if (inner) return blocked.check(inner, 'ipv4');
    // Any other IPv4-mapped form we didn't recognise is refused rather than guessed at.
    if (/^::ffff:/i.test(bare)) return true;
    return blocked.check(bare, 'ipv6');
  }
  return true;
}

const BLOCKED_HOST_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa', '.lan', '.intranet', '.corp'];

/** Host names that only mean something inside a private network. Checked before DNS. */
export function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === 'localhost' || !host.includes('.')) return true;
  return BLOCKED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix));
}
