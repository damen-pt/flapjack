# Tentacles: a fan-out control plane

Status: proposed, with a first implementation (`internal/pki`,
`internal/tentacle`, `internal/netsim`, the head's `/tentacle/v1` API in
`internal/server/tentacles.go`, agent enrollment in
`internal/agent/enroll.go`), wired into the CLI (`flapjack pki`,
`flapjack tentacle`, `flapjack agent`), `server.json` and `server
install`, with HTTPS boot. Tested in-process, over real TCP, and in the
Mac lab's default layout (`flapjack lab up`: a head, a tentacle per rack
running the rack's DHCP and boot, and Slurm on the nodes); not yet on
real hardware. Setup steps are in the
[administrator guide](../admin-guide.md#16-racks-and-tentacles).

## Why

One head node serving every agent directly works for tens of nodes. At a
thousand it breaks in three places, in this order:

1. **Switch fan-in.** `flapjack switch --all` wakes every agent at once.
   Each asks the head for the manifest and then each file. Before this
   change, every content request read and decoded the node's whole current
   generation from disk under one global lock, so about 50 files × 1000
   nodes queued behind one mutex.
2. **Status writes.** Each agent's first report on a new generation
   rewrote and fsynced all of `state.json`. That's 1000 full rewrites per
   switch, and the total cost grows with the square of the node count.
3. **Boot storms.** 1000 nodes pulling a 2 GB root filesystem from one NIC
   is 2 TB. That's about 3 minutes at 100 GbE line rate, and closer to 11
   at 25 GbE. Making the code faster doesn't fix it.

There's also a security problem that gets worse with scale: the head
identifies a node by the source IP of its request. That only works while every node is on the head's L2 segment. As
soon as anything sits in the middle (a routed rack, a cache, a relay), the
source IP is the middle's IP, and identity is gone.

## Shape

```
                 ┌─────────────── head ───────────────┐
                 │ store · generations · render · CAS │
                 │ cluster CA · generation signing key│
                 └────────▲──────────────────▲────────┘
          management core │ mTLS             │ mTLS
                 ┌────────┴───────┐ ┌────────┴───────┐
                 │  tentacle r1   │ │  tentacle r2   │   stateless, one per rack
                 │ cache · watch  │ │ cache · watch  │
                 └──▲──────────▲──┘ └──▲──────────▲──┘
        rack r1 mgmt│ mTLS     │       │          │ rack r2 mgmt
         ┌──────────┴┐    cluster r1   │    ┌─────┴─────┐
         │ r1n01..03 │◄── (100G) ──►   │    │ r2n01..03 │
         └───────────┘     tentacle    │    └───────────┘
                           chunk cache ┘
```

- **Head:** the authority. It owns the store, renders overlays, records
  generations, holds content by digest, runs the cluster CA and signs
  generations. Later this becomes 3–5 heads with Raft (see
  ARCHITECTURE.md, Scale); nothing in this design assumes a single head.
- **Tentacle:** one per rack (or per ~100–250 nodes). It's the same binary
  run as `flapjack tentacle`, it's stateless, and losing one only costs a
  cache. It keeps a single watch open to the head, caches the content its
  rack needs, serves its rack's agents, and relays their status reports
  and enrollments upstream. A tentacle is a relay, never an authority: it
  can't mint a generation, a certificate or a node identity.
- **Node:** runs the agent as before, but talks only to its rack's
  tentacle, and verifies what it receives against the head's signature,
  not against the tentacle.

### Networks

| Network | Speed (test) | Carries | Scope |
|---|---|---|---|
| Management core | 50 Gb/s | Head ↔ tentacles | Head and tentacles only |
| Rack management | 50 Gb/s per port | Agent ↔ tentacle: manifests, overlay content, status, enrollment | One rack; the head isn't on it |
| Cluster | 100 Gb/s per port | Staged artifacts (models, datasets) from the tentacle's chunk cache and from rack peers; job traffic | Leaf per rack plus a spine |

Nodes have no route to the head. Everything a node gets from the control
plane comes through its tentacle, so the head handles a number of
connections that grows with racks, not nodes.

## Identity

Each party has an X.509 certificate from the cluster CA. The identity is a
URI SAN, not a hostname or IP:

| Identity | Example | Issued by | Lifetime |
|---|---|---|---|
| Head | `flapjack://head/head` | Admin, at install | 30 days |
| Tentacle | `flapjack://tentacle/r1` (the name is the rack it serves) | Admin, `flapjack pki issue tentacle r1` | 30 days |
| Node | `flapjack://node/r1n01` | Head, at enrollment | 24 hours, renewed at half-life |

Certificates are Ed25519 and carry both server and client authentication
EKUs. Peers verify the chain against the cluster CA themselves and then
check the identity they expect: an agent accepts only
`flapjack://tentacle/<its rack>`, a tentacle only `flapjack://head/*`.
Hostname verification is replaced, not skipped. Short lifetimes stand in
for revocation lists. The head also refuses a tentacle not listed in its
config, so removing a tentacle from the config cuts it off at once.

Every connection is TLS 1.3 with mutual authentication, except a node's
first enrollment, which has no client certificate yet. Even that
connection is TLS 1.3, and the node authenticates the tentacle.

### Enrollment

A node boots with the cluster CA certificate (baked into the image) and its
rack and tentacle address on the kernel command line. It has no key.

```
node                         tentacle r1                        head
 │ TLS (server auth only)       │                                │
 │ POST /agent/v1/enroll        │ mTLS as tentacle/r1            │
 │  {node, mac, ticket, CSR} ──►│ POST /tentacle/v1/enroll ─────►│ node exists?
 │                              │                                │ node.rack == r1?
 │                              │                                │ ticket redeems for node's MAC?
 │                              │                                │ CSR self-signature valid?
 │ ◄──── cert flapjack://node/r1n01, 24 h ◄──────────────────────│ sign with cluster CA
```

The proof is the single-use, MAC-bound HMAC boot ticket from
`internal/attest` (see ARCHITECTURE.md, Node identity). The head issues
one only inside a *boot window*: DHCP answering that MAC's iPXE (the
request that hands iPXE its `.ipxe` script URL) opens a window of two
minutes, and issuing a ticket closes it. A script fetched from the node's
address outside a network boot, or a second time in one, boots without a
ticket, and the head records `boot.ticket_withheld`. PXE firmware's own
DHCP and an OS renewing its lease don't open a window. A TPM-resident CSR
key is not built yet.

The node generates its key locally, and only the CSR crosses the network.
The tentacle can see enrollment requests but can't use them: the ticket is
single-use and the head binds it to the node's MAC. A tentacle can't
enroll a node from another rack.

Renewal uses the same endpoint. A node holding a valid certificate sends a
CSR over mTLS, and the head reissues for the same identity, with no
ticket.

## Signed generations

mTLS protects each hop. It doesn't protect against a tentacle that has
been compromised. So the head also signs every generation it serves:

```
envelope  = {node, generation, digest = ManifestDigest(manifest), issued, signature}
signature = Ed25519(head key, "flapjack-generation-v2\x00" node "\x00" generation
                              "\x00" digest "\x00" issued)
```

The agent checks the signature with the head's public key (shipped with
the CA), recomputes the digest from the manifest it received, and refuses
the generation if either fails. Content was already verified by digest.
The node name is inside the signature, so a tentacle can't serve node A's
manifest to node B. Together these mean a compromised tentacle can
withhold updates or delay them, but can't change what any node applies.

**Replay.** A tentacle could still hold on to an old envelope, genuinely
signed, and serve it later to undo a change. `issued` is when the head
signed the envelope, in Unix nanoseconds, strictly increasing per head
(`pki.Signer`). The agent records the newest `issued` it has accepted, in
its state directory so a restart keeps it, and refuses anything older. A
rollback isn't a replay: the head signs the older generation afresh, with
a new `issued`. This relies only on the head's issue times moving forward,
not on node clocks. The head persists a floor a minute ahead of the newest
`issued` (`/var/lib/flapjack/generation-issued.floor`, written about once a
minute), so a restart or a backward clock step can't make it sign
envelopes that every agent would refuse as replays. With several heads (Raft), their clocks would need to
agree to within the time between two changes to one node, or `issued`
would come from the replicated log instead.

## Protocol

### Head ↔ tentacle (management core, mTLS)

| Call | What it does |
|---|---|
| `GET /tentacle/v1/watch?since=REV&wait=D` | Long-poll. Returns once the head's revision is past `REV`, with the full desired state for the tentacle's rack: every node's name, MAC, signed envelope and manifest. A full snapshot per change keeps the tentacle stateless; at 25–250 nodes per rack it's small. |
| `GET /tentacle/v1/content/{digest}` | Content, but only if some node in the caller's rack has that digest in its current generation. |
| `POST /tentacle/v1/status` | Batched agent reports: `[{node, report}]`. Rejected per entry for nodes outside the rack. |
| `POST /tentacle/v1/enroll` | Relayed enrollment and renewal; see above. |
| `GET /tentacle/v1/chunks/{digest}` | Staging chunks: artifacts and boot images. |
| `GET /tentacle/v1/boot/{mac}?window=0\|1` | A rack node's iPXE script, for a tentacle running the rack's DHCP. `window=1` says its DHCP just answered that MAC's iPXE, which opens the ticket window on the head. Refused for MACs outside the rack. |
| `POST /tentacle/v1/images` | `{versions}`: the boot image versions the tentacle has fully staged. Repeated every minute; the head stops trusting a report after 3 minutes. |

The rack is never a parameter. It comes from the tentacle's certificate.

### Node ↔ tentacle (rack management, mTLS)

The same `/agent/v1/*` API the head serves today (`manifest`, `content`,
`status`), plus `enroll`. Responses now include the signed envelope. The
tentacle identifies the node from its certificate and refuses any node
not in its rack's snapshot.

### Fan-out on a switch

1. `flapjack switch` records new generations on the head and bumps the
   revision once per node it changed.
2. Every tentacle's watch returns at once.
3. Each tentacle computes the set of digests its nodes need that it
   doesn't have, and fetches them with bounded parallelism. Content is
   addressed by digest and mostly shared within a class, so the head
   sends each file about once per rack, not once per node.
4. Only when all of a node's content is in the cache does the tentacle
   publish that node's new generation locally and wake its long-poll. The
   agent then pulls everything over the rack network.

So with R racks and N nodes, the head handles about R requests per changed
file, instead of N. Which nodes switch is still the admin's choice
(`flapjack switch NODE…`), so waves work unchanged; the tentacle only
makes each wave cheaper.

### Staged artifacts on the cluster network

A tentacle also serves the `internal/staging` chunk API on the cluster
network, behind the same mTLS. It pre-warms from the head's origin once
per rack. Agents fetch artifacts by trying rack peers first, then the
tentacle (`staging.TierRack`), then never the head, because nodes can't
reach it.

### Boot images from the rack

With `tentacleBoot` set for a rack on the head, and `bootListen` on its
tentacle, boot storms fan out the same way:

1. The head resolves each rack node's class image to its version
   directory (versions are immutable; a rebuild makes a new one and moves
   the link). It chunks each version's `vmlinuz`, `initrd.img` and
   `rootfs.squashfs` into the staging origin in the background, once,
   and then lists the version, with its manifests, in the rack snapshot.
2. The tentacle fetches the chunks it lacks from the head (shared chunks
   between versions aren't fetched again), assembles each file under
   `images/<version>/`, verifying it against the manifest's digest, and
   only then reports the version as staged. Versions the rack no longer
   boots are deleted.
3. A node's iPXE script then tries the tentacle first and the head
   second:

   ```
   kernel https://10.1.1.1/images/el9-2/RACKTOKEN/vmlinuz … root=live:https://10.1.1.1/images/el9-2/RACKTOKEN/rootfs.squashfs … && initrd … && imgverify … && boot ||
   echo flapjack: rack image cache did not answer; booting from the head
   kernel https://10.99.0.1/images/el9-2/HEADTOKEN/vmlinuz … root=live:https://10.99.0.1/…
   ```

   Both lines carry the same single boot ticket. Each carries an image
   token for that node's address and that version: the head's for the
   head line, and one under the rack's derived key for the rack line. A version the tentacle
   hasn't reported (a fresh rebuild, a tentacle that went quiet or was
   removed from `tentacles`) boots from the head.

The tentacle's boot listener uses an RSA certificate from the **boot CA**
(`flapjack pki issue tentacle r1 --boot-address 10.1.1.1`), because that's
what iPXE trusts, and asks for no client certificate, because iPXE and
dracut have none. Instead, like the head's boot listener, it serves an
image file only with a token from that node's script: the head mints
them during the node's boot window, bound to the image version, the
node's address and an hour. The tentacle checks them with
`HMAC(imageKey, "rack|r1")`, sent in its rack's snapshot, which can't
mint tokens the head or another rack would accept.

### Signed boot

HTTPS proves only that the server holds a boot-CA certificate, and a
tentacle has one. So boot is always signed: the head signs what it means
a node to run and the node checks it:

| What | Signed how | Checked by |
|---|---|---|
| Kernel, initrd | Detached CMS signature (`<file>.sig`) with the head's code-signing key from the boot CA, once per image version. Carried to tentacles in the rack snapshot and served beside the files | iPXE `imgverify`, before `boot`. On the rack line a failure falls through to the head |
| Root filesystem | Its sha256 on the kernel command line, `flapjack.rootfs=sha256:…` (too big for iPXE, and dracut fetches it, not iPXE) | The `flapjack-verify` dracut module in the (verified) initrd, at pre-pivot: it hashes the downloaded image, already in RAM, and refuses to switch root on a mismatch |
| The script | Every script, as served, signed by the head (`<mac>.ipxe.sig`, kept 10 minutes for that MAC). A tentacle relays both and holds no key | iPXE built with `EMBED=ipxe-embed.ipxe` (`imgtrust --permanent`, then fetch, `imgverify`, `chain`). With `imgtrust --permanent`, iPXE won't execute anything unverified, including the re-fetch a waiting node does |

Run in the Mac lab (aarch64 nodes, iPXE master `e6555a5`), it boots to
login with every check passing, and refuses a root filesystem with 4 KiB
appended (in the initrd) and a kernel with 512 bytes appended (in iPXE).
Three things the lab found, now fixed: iPXE's `TRUST=` holds only
fingerprints, so the boot listener must send the root with its
certificate. iPXE 2.0 offers TLS 1.3 and its handshake with Go fails, so
the boot listener caps at TLS 1.2. And iPXE on UEFI passes every image it
holds to the kernel as one initrd, so the script frees the others first.

The signatures use RSA with sha256, no signed attributes and the signer
certificate included, which is what `openssl cms -sign -binary -noattr`
writes and what iPXE reads. `TestDetachedSignatures` checks against
OpenSSL in both directions.

What this doesn't cover is the start of the chain. Firmware loads the iPXE
binary itself unverified, unless UEFI Secure Boot checks it. For a rack
whose tentacle only serves images (`tentacleBoot`), iPXE comes from the
head, so the chain holds from the head's iPXE onwards. For a rack whose
tentacle runs DHCP (`tentacleDHCP`), the tentacle serves iPXE too. A
compromised tentacle could then serve an iPXE that skips the checks, and
only Secure Boot (with a signed iPXE), or measured enrollment once it
exists (phase 5), stops that.

A link move outside the head (`flapjack image build` on another host) is
picked up within one watch period (1 minute): every watch reply, even one
with no overlay change, carries the rack's current image versions.

### DHCP on the rack

With `tentacleDHCP` listing a rack on the head and `dhcp` set on its
tentacle, the tentacle carries the whole boot and the rack's nodes need
no path to the head at all. The alternative, a DHCP relay to the head,
would keep the head on the boot path of every node, and would need the
rack routed to it.

```
firmware ──DHCP──► tentacle: lease from the rack snapshot, file ipxe-x86_64.efi
firmware ──TFTP/HTTP──► tentacle: iPXE (staged from the head, built with TRUST=boot-ca.pem)
iPXE ──DHCP──► tentacle: file https://10.1.1.1/boot/<mac>.ipxe; boot window opens
iPXE ──HTTPS──► tentacle ──mTLS──► head: GET /tentacle/v1/boot/<mac>?window=1
                                   head: script pointing only at the tentacle, one ticket
iPXE ──HTTPS──► tentacle: kernel, initrd; dracut: root filesystem
```

- **Leases** come from the rack snapshot, which now carries each node's
  interfaces and addresses. The tentacle answers only interfaces whose
  reserved address is in its DHCP subnet, so a node's cluster NIC is left
  to whatever serves that network. The head's own DHCP ignores MACs of
  `tentacleDHCP` racks, in case a segment is shared.
- **iPXE binaries** (`*.efi`, `*.kpxe` from the head's boot directory) go
  out in the snapshot as staging manifests. The tentacle stages them into
  `dataDir/ipxe/`, re-fetching only one that changed, and serves them
  over TFTP and HTTPS, and over plain HTTP only with `dhcp.plainHTTP`, for
  UEFI HTTP-boot firmware that can't do HTTPS to a private CA. Scripts and
  images are never served over plain HTTP.
- **Scripts** still come from the head, because the head issues tickets.
  The tentacle checks the request came from the address it leased that
  MAC, and says whether its DHCP opened a boot window. The head's script
  points only at the tentacle; if the tentacle hasn't staged the version
  yet, the node waits and asks again every 30 s instead of falling back
  to a head it can't reach.
- **Trust.** The tentacle now decides when its rack's boot windows open,
  so a compromised tentacle can obtain tickets for its rack's nodes. That
  gives it nothing it lacks already, since it sees the rack's overlay
  content. It still can't get a script or ticket for another rack's node,
  or alter a signed script, kernel, initrd or root filesystem. It does
  serve the rack's iPXE binary; see Signed boot for what that leaves
  open.

## Failure behaviour

| Failure | Effect |
|---|---|
| A tentacle dies | Its rack keeps running what it has. Agents retry with backoff. A replacement tentacle with the same certificate takes over with no state to restore, since it rebuilds its cache from the first watch. |
| The head is unreachable | Tentacles keep serving their last snapshot, and a DHCP tentacle keeps answering leases from it. Running nodes are unaffected; switches wait. A rebooting node can't get its script (the head writes it and issues the ticket), so it waits until the head is back. |
| A tentacle is compromised | It can withhold or delay updates for its rack, and see that rack's overlay content, but not its secrets, which it only ever holds sealed to their node (HPKE to a key each node makes at enrollment). To read a node's secrets it must race that node's next boot for its ticket, which revokes the real node's certificate and fails its enrollment, loudly. It can't forge generations, enroll nodes outside its rack, or read other racks' content. It can't alter its rack's kernels, initrds, root filesystems or scripts either: they're signed by the head and checked by iPXE and the initrd (signed boot). With `tentacleDHCP` it serves its rack's iPXE binary, which nothing checks without UEFI Secure Boot. |
| A node is compromised | It gets its own content and nothing else. Its certificate expires within 24 h unless renewed, and the head can stop renewing. |

## Single-head fixes made alongside

- `gens.Store` caches each node's current generation in memory, so content
  checks and long-poll wakeups no longer read and decode JSON from disk.
- The head has a revision counter and a broadcast for tentacle watches.
- Agent reports are soft state, so the store coalesces their writes:
  `ReportAgent` updates memory and schedules one write within 2 s, which
  carries every report that arrived meanwhile. Any other change (spec,
  phase, enrollment) is on disk before it returns, and takes pending
  reports with it; the server flushes on shutdown. A crash loses at most
  2 s of reports, which agents send again.
- Those writes are group-committed: a change is made in memory and the
  writer waits for a write of the file that includes it, done outside the
  store lock. Writers that arrive while one write is under way share the
  next. At 10,000 nodes one write of the file takes about 90 ms on NVMe,
  so an enrollment storm costs a write every 90 ms rather than one per
  node, and DHCP and boot lookups never wait on the disk.
- The store indexes nodes by MAC and IP, so DHCP, boot scripts and every
  agent request look a node up in O(1) instead of scanning all nodes;
  `PutNode`'s uniqueness check uses the same index.
- Agents jitter their long-poll (between half and all of `Verify`), their
  retry backoff and their enrollment retries; tentacles jitter their
  reconnect backoff. Nodes that switched or lost the head together spread
  out instead of returning in lockstep.

## Test topology

`internal/tentacle/cluster_test.go` builds this cluster in-process,
using `internal/netsim`, and `tentacle_test.go` runs the scenarios:

```
                       core-mgmt switch (50G)
                    ┌────────┼──────────┐
                  head   tentacle r1   tentacle r2
                           │    │        │    │
           r1-mgmt switch ─┘    │        │    └─ r2-mgmt switch
           (50G)  r1n01..03     │        │       (50G) r2n01..03
                                │        │
           r1-cluster switch ───┘        └─── r2-cluster switch
           (100G) r1n01..03 ─── spine (100G) ─── r2n01..03
```

`netsim` is a userspace fabric. Hosts have interfaces on switches, and
switches connect by links with a speed in bits per second. A connection
only exists between two interfaces in the same connected set of switches,
so a rack node really can't reach the head. Each link direction is a
shared rate limiter, so concurrent flows split its bandwidth. Every byte on
every link goes through a tap. Real TLS, HTTP, server, tentacle and agent
code run over it unchanged.

`TestTwoRacks` (real speeds) asserts:

- Every node enrolls with a single-use boot ticket through its tentacle,
  and gets a certificate for its own name.
- A switch reaches all six nodes. Status reports reach the head batched,
  not one request per report.
- Each tentacle fetches each file from the head once per rack: four
  fetches for three per-node files and one shared file. The secret comes
  once per node, sealed to that node, and is never fetched or cached in
  the clear (a copy planted in the cache is deleted on the next snapshot).
  A one-file change costs each tentacle exactly one fetch.
- Nodes have no route to the head or to the other rack's management
  network. The cluster spine does reach the other rack's tentacle, but
  that tentacle refuses the node at the TLS handshake.
- Tentacle r1 can't read r2's content, enroll r2's nodes or report for
  them. A tentacle removed from the head's list is refused on new
  handshakes and on requests over connections already open.
- Enrollment refuses reused tickets and tickets for another node's MAC.
  Renewal refuses a proof made with another node's key, and the tentacle
  refuses a node enrolling under another name.
- A compromised tentacle (holding r1's real key, on r1's switch) that
  tampers with a file, re-signs a generation with its own key, serves
  another node's genuine generation, or strips the signature is refused
  by the agent every time, and nothing is written. So is a genuine,
  head-signed generation 1 replayed to an agent that has since accepted a
  newer one, while a real rollback to generation 1 goes through.
- Node certificates (6 s lifetime in the test) renew through the
  tentacle, and agents keep converging afterwards.
- A 3 MiB artifact reaches all six nodes over the cluster network from
  their tentacle's cache. The head serves each chunk once per rack, and
  its port carries the artifact about twice, not six times.
- All connections (60-odd) across 22 links start with a TLS handshake, and
  none contains overlay content, the munge secret, any boot ticket, PEM
  keys or certificates, `flapjack://` identities, API paths, JSON, or
  artifact bytes in plaintext.

`TestNetworkSpeeds` runs the same topology scaled down 1000× (50 and
100 Mb/s), so the link limit, not memory copying, is what's timed. It
sends 2 MiB over mTLS from the tentacle on each network and keeps the
best of three runs, since load can only slow a transfer down. Measured:
390 ms over management against an ideal of 336 ms, and 203 ms over cluster
against an ideal of 168 ms, a ratio of 1.92 (about 1.4× ideal under
`-race`). It fails below 0.9× ideal, which would mean the limit isn't
enforced, or above 2.5×. `-short` skips it.

`TestServeFromFiles` runs a tentacle the way `flapjack tentacle` does,
over real TCP, from files laid out by `pki init` and `pki issue`. A node
enrolls, its saved identity is reused without a ticket, and it applies a
signed generation. `internal/server` tests that plain HTTP (when on)
serves only iPXE binaries, that images need a token for their version
from their address, that a redeemable ticket is only in scripts served
inside a boot window, and that the boot listener negotiates TLS 1.2 with ECDHE-RSA-AES-GCM, as iPXE does,
while refusing CBC suites and TLS 1.1.

`TestBootImagesFromTentacle` runs the boot-image path over real TCP: a
5 MiB root filesystem staged once per chunk, the script routed to the
tentacle only after it reports the version (with the head as fallback and
one ticket on both lines), an iPXE-like TLS 1.2 client trusting only the
boot CA downloading every file, no path outside the image directory, a
rebuild that changes only the kernel fetching exactly one new chunk and
pruning the old version, and a delisted tentacle getting no more boots.
`internal/server` tests that tickets are only issued inside a boot window,
once, and that only iPXE's DHCP opens one.

`TestRackBootFromTentacle` runs a DHCP tentacle against a real head over
TCP: DHCP answers PXE and iPXE from the snapshot (and nothing for another
rack's node, an unknown MAC or the node's NIC on another subnet), iPXE
binaries are staged and served (and nothing else from the boot
directory), the script is not served over plain HTTP or to another
address, a script outside a boot window has no ticket or image token, iPXE's DHCP opens one for
exactly one fetch, the script points only at the tentacle (no head
fallback), the head refuses r7's tentacle a script for r8's node, a
version not yet staged makes the node wait, and with the head down DHCP
still answers while the script fails.

Signed boot is tested at each layer: `internal/pki` signs and verifies
with OpenSSL in both directions and refuses tampered content and a
signer from another boot CA. `internal/server` checks every script
imgverifies kernel and initrd before `boot`, carries the root
filesystem's digest, and has a signature served only to the node's
address that stops verifying after a one-word change. `internal/image`
runs the dracut hook under `/bin/sh` against a fake `/sys`: it accepts the
genuine image, refuses an altered one, and refuses when it finds nothing
to check. The tentacle tests swap a staged kernel and edit a relayed
script, and neither verifies.

One bug the test found and fixed: an agent's HTTP client reused the
unauthenticated connection from its enrollment, so the tentacle kept
treating it as anonymous. `Credentials` now drops pooled connections
whenever its certificate changes.

## Phases

1. *Done:* PKI, signed generations, tentacle relay and cache, head
   tentacle API, agent mTLS and signature checks, generation cache,
   in-process topology test.
2. *Done:* replay protection; `flapjack pki init|issue|show`, `flapjack
   tentacle` and `tentacle.json`; `server.json` fields; `server install`
   creating the PKI; agent flags and kernel arguments; a boot ticket,
   tentacle and rack on the kernel command line; images carrying the
   public CA, generation key and boot CA.
3. *Done, run in the Mac lab:* HTTPS boot, signed boot, image tokens
   and boot windows, always on (there is no plaintext mode). Scripts,
   kernels, initrds and root filesystems are served over HTTPS only,
   with a separate RSA boot CA and TLS 1.2 (what iPXE speaks); DHCP hands
   iPXE an `https://` script URL. `flapjack lab` builds iPXE on the head
   against its boot CA and boots nodes with it.
4. *Done, untested on hardware:* tentacles stage and serve boot images to
   their rack, with the head as fallback, and can run their rack's DHCP,
   serve iPXE over TFTP and HTTP, and relay scripts, so a rack boots
   without any path to the head.
5. TPM-backed enrollment, with the boot measured.
6. Head HA with Raft. A tentacle's watch fails over to any head.
7. Mac lab topology: `flapjack lab` with `tentacles: true` and two
   networks; signed x86_64 iPXE in the lab.

## Open questions

- **Rack size:** at what rack size should a tentacle become two? The watch
  snapshot is O(rack); beyond about 500 nodes, switch to per-node deltas.
- **Tickets and the boot network:** a ticket and image tokens go only to
  the first bootable script fetched from the node's reserved address in
  its boot window. With `bootWindow: dhcp`, DHCP opens the window, so
  anything that can spoof the node's MAC can open one, and so can the
  rack's tentacle (`window=1`). With `armed` (the default), only
  flapjack's BMC power actions, the agent's reboot notice (signed by the
  node's key, so a tentacle cannot forge or replay one), an admin or the
  BMC watcher do. Either way an attacker holding the node's address
  during a real window, or the tentacle relaying the script, can still
  race it; the winning enrollment revokes the node's other certificates
  (`pki.superseded`) and the real node's enrollment fails as
  `pki.enroll_refused`. TPM enrollment is what closes this.
- **The iPXE binary on tentacle-DHCP racks:** signed boot protects
  everything after iPXE. The binary itself is only protected by UEFI
  Secure Boot (a shim-signed iPXE) or detected by measured enrollment.
  Until one of those exists, `tentacleDHCP` trusts the tentacle with the
  rack's iPXE.
