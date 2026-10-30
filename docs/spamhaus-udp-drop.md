# Spamhaus UDP DROP

This opt-in extension uses **The Spamhaus Project DROP** CIDR datasets already
loaded by Spamhaus OUTPUT. Source and dataset policy:
https://www.spamhaus.org/blocklists/do-not-route-or-peer/

It is not a UDP C2 IP:port feed. It blocks UDP in the original conntrack direction
to listed IPv4/IPv6 networks, across destination ports. TCP and reply-direction
packets are not matched. It does not stop UDP abuse toward unlisted networks.

The existing Spamhaus observer owns the v4/v6 sets and their download/cache/update
lifecycle. This extension adds only two DROP rules and two exemption sets in the
same owned table; it does not change INPUT, the TCP C2 table, udp_pairs, routes or
container configuration. Observer updates change the referenced sets atomically;
no duplicate download or new feed timer is added. Counters and logs remain present.

Commands: enable-block, disable-block, restore, status. No command installs units
or starts/enables services automatically. The executable is deployed separately to
/usr/local/sbin/xtls-spamhaus-udp. The supplied restore unit runs after and requires
xtls-spamhaus-output-restore.service. Deployment and enabling are explicit steps.
Do not install over unknown existing files/units. No menu integration is included
in this first PR.

Before enabling, create /etc/xtls-spamhaus-udp/exemptions.txt with reviewed IPs/CIDRs
(one per line, optional # comments). Include required infrastructure endpoints as
appropriate. An explicitly empty reviewed file is allowed; a missing file, symlink,
invalid network or /0 exemption is rejected. Never ship private infrastructure IPs
as repository defaults. Review exceptions locally; they bypass only this module's
UDP DROP, not other firewall layers.

Mode is separate from the observer: /etc/xtls-spamhaus-udp/mode. Absent mode means
observe. Unknown mode refuses restore. Source sets must exist, have correct types
and be nonempty before enabling. Own rules and exemptions change as one nft batch,
with syntax validation before apply. Disable persists observe before removing all
exactly tagged rules, and verifies removal. Boot restore heals saved observe/live
block mismatches. A failed enable never reports success or persists new block.

Use a timed automatic disable during the first production enable, then verify
SSH, VPN and UDP applications before cancelling it. The generic observer module
must remain installed; do not manually delete its shared table while this module
is active. No automatic bans or subscription state changes are performed.
