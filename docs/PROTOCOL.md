# Cyclades relay protocol, version 0

- Status: draft, not audited. Validated design; the reference relay is not published yet. Default limits are provisional (section 16).
- Version: 0, October 2026 (design started in May 2026).
- Authors: the Cyclades project.
- Contact: security issues privately via the Security tab (Report a vulnerability); everything else in GitHub issues.
- License: CC BY-SA 4.0, https://creativecommons.org/licenses/by-sa/4.0/
- Related, not published yet: `MESH.md` (Bluetooth mesh), `CLIENT-CRYPTO.md` (client cryptography), `NEARBY.md` (recognising nearby contacts).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119.

## 1. Purpose

A Cyclades relay stores and forwards opaque encrypted envelopes between Cyclades clients when they have Internet access. Clients exchange messages phone to phone over Bluetooth when they do not. The relay is one of two transports, never the only one.

All encryption happens on devices. The relay never sees plaintext, never holds a user account, and is designed to learn as little as possible about who talks to whom.

## 2. Threat model

### 2.1 What the relay never learns

- Message content. Envelopes are encrypted end to end by clients.
- The long-term identity of senders or recipients. There are no accounts, no phone numbers, no durable keys presented to the relay.
- The exact size of a message. Envelopes come in fixed size tiers.
- Precise timestamps of stored envelopes. Only an expiration rounded up to the hour is stored.

### 2.2 What a relay can still observe

These leaks are inherent to an online relay. The protocol limits what an honest relay stores and what a seized relay reveals. It cannot stop a malicious operator who modifies the relay software to record everything it sees in real time:

- The IP address of each connection.
- Which connection deposits to which mailbox, and when.
- Which mailboxes a single connection joins, which links those mailboxes together.
- The size tier of each envelope and the activity volume of each mailbox.
- For a group mailbox (section 5.2): the connections that join it, so the network addresses of its members and the size of the group. Its envelopes are never acknowledged, so a seized relay holds up to 24 hours of them, read or not.

Clients reduce these leaks with the measures in section 12 (mailbox rotation, one mailbox per connection, anonymizing networks such as Tor).

### 2.3 Adversaries considered

- A curious but honest operator reading the relay's disk and logs.
- Someone who seizes the relay and performs forensic analysis of its storage.
- A network observer between clients and the relay.
- A flooder trying to fill mailboxes or exhaust the relay.

### 2.4 Non-goals for version 0

- Hiding from the relay that a client uses Cyclades, or hiding its IP address. Clients that need this use Tor or a VPN.
- Federation between relays and bridging of Bluetooth mesh islands (section 14).
- Push notifications (section 14).

## 3. Conventions

- Binary values are encoded as base64url without padding (RFC 4648, section 5). Only the canonical encoding is accepted: the unused low bits of the last character MUST be zero. A 32-byte value takes 43 characters, the last one carrying 2 unused bits, so up to four strings would otherwise decode to the same bytes. The relay decodes, re-encodes and compares, rejects any difference with `invalid_payload`, and keys everything by the raw bytes, never by the string. Otherwise a second spelling of a `mailbox_id` would get around real-time delivery (section 7.6) and per-mailbox limits.
- `a || b` is the concatenation of byte strings. ASCII literals such as `"cyclades/v0/join"` are their raw bytes with no terminator.
- Every field concatenated after a literal has a fixed length, so no length prefix is needed.
- Signatures are Ed25519 as defined in RFC 8032 (pure Ed25519, no prehash, no context), verified with the strict rules of section 5.1. Hashes are SHA-256.

## 4. Transport

- Phoenix Channels over WebSocket, at `/relay/websocket`, with the Phoenix V2 JSON serializer (`vsn=2.0.0`).
- TLS is REQUIRED in production. It is usually terminated by a reverse proxy in front of the relay.
- The socket connection carries no parameters and no identity.
- Messages larger than 32 KiB are rejected and close the connection, whether they come in one frame or in fragments.
- The client completes a message at least every 30 seconds: a Phoenix heartbeat (topic `phoenix`, event `heartbeat`) when it has nothing else to send. A relay MAY close a connection that completes no message for a minute, whatever bytes arrive (section 9.4).

## 5. Mailboxes and keys

A mailbox is the address where a recipient collects envelopes.

- The recipient generates a temporary Ed25519 key pair for each mailbox. It MUST NOT be derived from, or reused as, a long-term identity key.
- `mailbox_id = SHA-256("cyclades/v0/mailbox" || mailbox_pubkey)`, 32 bytes.
- Senders only need the `mailbox_id`. Recipients share it with their contacts through the end-to-end encrypted layer, or out of band (QR code, Bluetooth).
- The relay keeps no mailbox registry. A mailbox exists on the relay only while it holds envelopes. Depositing to an unknown mailbox is valid, which gives no oracle on whether a mailbox is in use. The cost this opens on the relay's storage is bounded by section 9.

### 5.1 Signature verification

Every party that verifies a signature (the relay today, clients and federated relays later) MUST apply these checks before calling any library verification function, and reject the input if one of them fails:

1. The public key `A` is 32 bytes and the signature is 64 bytes.
2. `S`, the last 32 bytes of the signature read as a little-endian integer, is lower than the group order `L = 2^252 + 27742317777372353535851937790883648493`.
3. `A` and `R` (the first 32 bytes of the signature) are canonical: with the top bit cleared, their little-endian value is lower than `p = 2^255 - 19`.
4. Neither `A` nor `R` has small order. With the top bit cleared, their encoding is none of the following:

```
0000000000000000000000000000000000000000000000000000000000000000   order 4
0100000000000000000000000000000000000000000000000000000000000000   order 1
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05   order 8
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a   order 8
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f   order 2
```

Only then does the verifier apply RFC 8032 verification.

These checks are mandatory, not redundant: libraries disagree on these inputs. Erlang/OTP 29 rejects test vector N1 but accepts N2, a signature anyone can produce for a small-order key (section 15). With the checks in place, every conforming implementation gives the same answer for any signature made with an honestly generated key, and signatures cannot be altered into a second valid form.

One divergence remains. A key with a small-order component (mixed order) can be crafted so that implementations using cofactored and cofactorless verification disagree. Only someone crafting their own mailbox key can produce one, and since the `mailbox_id` commits to the key, it only affects that person's own mailbox. Keys MUST be generated with a standard library (CryptoKit, libsodium, Erlang/OTP), which never yields such keys.

### 5.2 Group mailboxes

A group mailbox is shared by the members of a group, who read it without deleting anything (`CLIENT-CRYPTO.md` section 7).

- `group_mailbox_id = SHA-256("cyclades/v0/group" || group_pubkey)`, 32 bytes. Group mailboxes form a namespace of their own: the relay keys envelopes by kind and id, so a group mailbox and a private mailbox with the same 32 bytes never share envelopes. A deposit marked as group to the id of a private mailbox lands where nobody can join, like a deposit to an invented mailbox.
- Deposits and joins say `"group": true` (sections 7.1 and 7.2).
- Every envelope of a group mailbox expires 24 hours after its deposit (`group_ttl`), whatever `ttl` the deposit asks for. 24 hours is also the `max_ttl` of pressure mode (section 9.3), so expiration follows the order of deposit, in pressure mode too. Section 7.3 relies on it.
- Envelopes of a group mailbox leave by expiration only. `ack` and `purge` are refused, so no member, and no seized member phone, can delete them for the others.
- The relay keeps no registry of group mailboxes either: one exists only while it holds envelopes.

## 6. Session

When a socket connects, the relay generates a `nonce` of 32 random bytes. It is bound to that connection and is never reused. A new connection always gets a new nonce.

The client joins the topic `session` with:

```json
{"protocol": 0}
```

The relay replies with:

```json
{
  "nonce": "<32 bytes>",
  "tiers": [1024, 4096, 16384],
  "min_ttl": 3600,
  "max_ttl": 604800,
  "max_mailboxes": 32,
  "fetch_limit": 100,
  "fetch_max_bytes": 524288,
  "pow_bits": 0,
  "full": false
}
```

`fetch_limit` and `fetch_max_bytes` bound a fetch reply (section 7.3).

`max_ttl`, `pow_bits` and `full` reflect the relay's current state and change in pressure mode (section 9.3). `full` is true once the smallest envelope no longer fits under the storage cap. Connected clients learn about changes in two ways:

- When one of these values changes, the relay broadcasts the event `state` on `session` to every connection: `{"max_ttl": 86400, "pow_bits": 21, "full": false}`.
- Every reply to `deposit`, success or error, carries the current `max_ttl`, `pow_bits` and `full`.

A relay that does not support the requested version replies with the error `unsupported_protocol`.

## 7. Operations

### 7.1 deposit

Anyone can deposit. The sender is not authenticated and stays anonymous to the relay. Rate limits (section 9) are the only protection against abuse.

Event `deposit` on topic `session`:

```json
{"mailbox_id": "<32 bytes>", "blob": "<1024, 4096 or 16384 bytes>", "ttl": 86400, "pow": "<64 bytes>", "group": false}
```

- `blob`, once decoded, MUST be exactly one of the size tiers. Any other length is rejected with `invalid_size`.
- `ttl` is optional and given in seconds. It defaults to `max_ttl` and is clamped to `[min_ttl, max_ttl]`.
- `group` is optional and defaults to `false`. With `true`, the envelope goes to the group mailbox `mailbox_id` (section 5.2): `ttl` is ignored, the envelope expires after `group_ttl`, and the group quota applies (section 9.1).
- `pow` is required only in pressure mode (section 9.3). Without a sufficient proof, the relay replies `pow_required`.
- On success the relay stores the envelope and replies with the current state, `{"max_ttl": 604800, "pow_bits": 0, "full": false}`. Success means stored, not delivered.
- The relay checks a deposit in this order, and replies with the first failure: `invalid_payload` and `invalid_size`, then `rate_limited`, then `pow_required`, then `relay_full`, then `mailbox_full`. In pressure mode, only a depositor who paid the proof therefore learns whether the relay or a mailbox is full.

### 7.2 join a mailbox

Topic `mailbox:<mailbox_id>`, join payload:

```json
{"pubkey": "<32 bytes>", "sig": "<64 bytes>", "group": false}
```

where

```
sig = Ed25519-Sign(mailbox_secret_key, "cyclades/v0/join" || nonce || mailbox_id)
```

The relay accepts the join only if:

1. `SHA-256("cyclades/v0/mailbox" || pubkey)` equals the `mailbox_id` of the topic, and
2. `sig` is a valid signature of `"cyclades/v0/join" || nonce || mailbox_id` under `pubkey`, using the nonce of this connection.

Otherwise it replies `unauthorized`. Both checks fail with the same error.

For a group mailbox, the join says `"group": true` and check 1 becomes `SHA-256("cyclades/v0/group" || pubkey)`. The signed message is the same.

A connection MAY join up to `max_mailboxes` mailboxes. The signature is computed once per join. The channel process then stays bound to the mailbox, so `fetch`, `ack` and `purge` need no further signature. Replaying a join signature on another connection fails because the nonce differs.

A mailbox is joined by at most 4 connections at once if it is private, and 128 if it is a group mailbox. Beyond that the join is refused with `mailbox_busy`, and a place frees when one of those connections leaves or closes. These bounds keep one deposit from being pushed to an unbounded number of connections (section 7.6). 4 leave room for a phone whose previous connections have not yet been closed after a network change: the relay closes a silent connection after 60 seconds, so a client refused with `mailbox_busy` retries later. 128 is more than twice the 50 members of the largest group (`CLIENT-CRYPTO.md`, D3): when the mobile network drops for a whole crowd at once, every member comes back on a new connection while its previous one keeps its place for up to 60 seconds. The cost for groups is in section 9.1.

### 7.3 fetch

Event `fetch` on a joined mailbox topic:

```json
{"limit": 100, "after": "<16 bytes, optional>"}
```

Reply:

```json
{"envelopes": [{"id": "<16 bytes>", "blob": "<bytes>"}], "more": false}
```

- Envelopes are returned in ascending order of `id` (byte order). `after` pages through them.
- `limit` is capped at `fetch_limit`.
- A reply also stops before the envelope that would take its blobs past `fetch_max_bytes`, but always holds at least one envelope, and `more` is then true. A reply can therefore hold fewer than `limit` envelopes while more remain: the client pages on as long as `more` is true. This holds for group mailboxes too.
- The order carries no meaning. Ids are random, so it is not the deposit order. Clients rely on timestamps and counters inside the encrypted payload.
- Expired envelopes are never returned, even if they have not been purged yet.
- Because ids are random, an envelope deposited during pagination can sort before the current `after` cursor and be skipped. After acknowledging a batch, the client MUST start again from the beginning (without `after`), and repeat until a fetch returns no envelope.

**Group mailboxes.** A fetch reads without deleting and takes `since`, so that a member does not read the whole mailbox at each visit:

```json
{"limit": 100, "since": 1793289600, "after": "<16 bytes, optional>"}
```

- `since` is an expiration hour, in Unix seconds, a multiple of 3600; any other value is rejected with `invalid_payload`. The relay returns the envelopes whose `expires_at` is at or after `since`, in ascending order of `expires_at`, then of `id`, each as `{"id", "blob", "expires_at"}`. Without `since`, the fetch starts from the oldest envelope.
- To page through, the client sends `since` = the `expires_at` of the last envelope received and `after` = its id. The relay returns what comes strictly after the pair (`since`, `after`) in that order: a later `expires_at`, or the same one and a greater `id`. It does not look that envelope up, so the cursor still holds when the envelope has expired in between, at each change of hour. `after` without `since` is rejected with `invalid_payload` on a group mailbox.
- On a private mailbox, `since` is rejected with `invalid_payload`.
- `since` reveals nothing new: `expires_at` is already stored, and it already gives away the hour of deposit (section 8). A cursor based on a deposit counter would reveal how many messages the group has exchanged since its mailbox first held an envelope, so version 0 has none.
- Within one expiration hour, the order is that of the random ids, so an envelope deposited during the pagination can sort before the cursor and be skipped, as above. A member MUST therefore join the group mailbox before fetching, so that real-time delivery (section 7.6) brings every envelope deposited in the meantime. It then fetches from the expiration hour of the last envelope it already holds, drops the envelopes it already has, and stops when a full pass from that `since` brings nothing new.

### 7.4 ack

Event `ack` on a joined mailbox topic:

```json
{"ids": ["<16 bytes>", "..."]}
```

At most `fetch_limit` ids per call. The relay deletes the listed envelopes that belong to this mailbox, ignores the others without saying so, and replies `{}`. Acknowledging the same id twice is harmless. On a group mailbox, `ack` is refused with `not_allowed`.

### 7.5 purge

Event `purge` on a joined mailbox topic, empty payload. It deletes every envelope of the mailbox and replies `{}`. A client uses it when it abandons a mailbox, for example after a flood. On a group mailbox, `purge` is refused with `not_allowed`.

### 7.6 Real-time delivery

When an envelope is deposited, the relay pushes the event `envelope` with `{"id", "blob"}` on the topic `mailbox:<mailbox_id>` to every connection that has joined that mailbox, with `expires_at` for a group mailbox. The envelope stays stored until it is acknowledged or expires.

Real-time delivery is best effort. A connection that does not read what the relay sends would keep every push in the relay's memory, so when more than 8 messages wait to be sent on a connection, the relay pushes nothing more to it and closes it with WebSocket close code 1013 (Try Again Later) rather than 1000 (Normal Closure), so that a client and a log can tell the two apart. A client that reads slowly may not get that close frame: it waits behind what the relay and any proxy in front of it have already buffered, and the relay closes the TCP connection one minute after sending it, so the client sees its connection cut, possibly in the middle of a message. It also closes a connection on which sending one message stays blocked for 5 seconds. Nothing is lost: the envelopes stay stored, and the client gets them by fetching once it has joined again (section 12). On a 1013, as on any closing, the client reconnects on its own.

## 8. Envelopes

An envelope holds:

| Field | Content |
|---|---|
| `id` | 16 random bytes from a CSPRNG |
| `mailbox_id` | 32 bytes |
| `blob` | exactly 1024, 4096 or 16384 bytes |
| `kind` | private or group (section 5.2) |
| `expires_at` | `now + ttl`, or `now + group_ttl` for a group mailbox, rounded up to a full hour (ceiling: a value already on a full hour stays as is) |

- No creation timestamp is stored. Rounding `expires_at` to the hour still reveals the deposit hour when the TTL is known. This one-hour granularity is the accepted residual leak.
- Ids are random, never sequential, so they reveal neither the global message volume nor the deposit order.
- Storage SHOULD NOT preserve insertion order: no auto-increment key, and the table is keyed by the random id.
- A periodic job deletes expired envelopes.

## 9. Quotas, rate limits and pressure mode

All values are configurable defaults, to be tuned with real traffic.

### 9.1 Quotas

| Scope | Limit | On overflow |
|---|---|---|
| Mailbox | 500 envelopes or 4 MiB, whichever comes first | `mailbox_full` |
| Group mailbox | 2000 envelopes or 16 MiB, whichever comes first | `mailbox_full` |
| Relay | total storage cap set by the operator (default 1 GiB) | `relay_full` |

When a mailbox is full, new deposits are refused and existing envelopes are kept. The relay never drops old envelopes to make room, because that would let an attacker flush legitimate messages. A flooded recipient gets around the attack on the client side by rotating mailboxes (section 12).

Group envelopes stay until they expire, read or not, since nobody acknowledges them. Like any deposit, they count against the byte budgets of their network origin (section 9.2) and against the storage cap that drives pressure mode (section 9.3), which bound the room they take.

A member of a group, or the seized phone of a member, can fill the group mailbox, at the per-mailbox rate of section 9.2 in 9 to 17 minutes, and silence the group at the relay for up to 24 hours: there is no purge to undo it. Version 0 accepts this cost. The admin then moves the group to a new group mailbox, as after a removal (`CLIENT-CRYPTO.md` section 7). If the flooder is not identified, the new mailbox can be flooded again, and the group falls back on the Bluetooth mesh.

In the same way, a member, or the seized phone of a member, can hold the 128 places of the group mailbox (section 7.2) with connections of its own, and keep the other members from joining it, so from reading it at the relay, for as long as it keeps them open. Version 0 accepts this cost too, for the same reason: only a member can join, and no relay-side rule tells a member who holds places from one who reads. The answer is the same: the admin moves the group to a new group mailbox, as after a removal, and the group falls back on the Bluetooth mesh if the culprit is not identified.

### 9.2 Rate limits and byte budgets

Limits apply per connection, per mailbox, per network origin, and to the whole relay for bytes served. The network origin is the IPv4 address, or the /64 prefix of an IPv6 address (section 11.2).

| Scope | Deposits | Bytes deposited | 16 KiB envelopes | Bytes served | Other |
|---|---|---|---|---|---|
| Connection | 300 / min | 2 MiB / min | 30 / min | 16 MiB / min | 30 joins and 120 fetches, acks and purges / min, at most `max_mailboxes` joined at once |
| Network origin | 3000 / min | 16 MiB / min and 256 MiB / hour | 300 / min | 16 MiB / min, at most 4 MiB at once | 600 joins / min |
| Mailbox | 120 / min | | | | |
| Relay | | | | 64 MiB / min, at most 16 MiB at once | |

Exceeding a limit returns `rate_limited`, or `too_many_mailboxes` for the number of joined mailboxes. Caps on connections are in section 9.4.

Each limit is a token bucket. It refills continuously at its rate and holds at most one minute of it (one hour for the hourly budget), or the amount given as "at most". A client that has waited long enough can spend a whole minute at once, but never two in a row: with fixed windows, it could spend one just before the turn of a minute and another just after. A request refused with `rate_limited` takes nothing from any bucket.

Bytes served are the envelope bytes of fetch replies. A fetch first takes `fetch_max_bytes` from its budgets and gives back what its reply did not use, so that concurrent fetches cannot overdraw them. A client that stops reading leaves its replies waiting in the relay's memory until the relay closes the connection, and per-origin budgets cannot bound that memory against an attacker who uses many addresses. The relay-wide budget does. Once it is used up, every fetch is refused with `rate_limited` until it refills: such an attacker can delay fetches for everyone, but cannot exhaust the relay's memory. Real-time delivery (section 7.6) does not count against it.

The budget of a network origin is a quarter of the relay-wide one: it takes at least four origins to use the relay-wide budget up, so one address alone cannot delay the fetches of everyone else. The bound is only as strong as the notion of origin: a subscriber holding a /56 has 256 IPv6 origins, and an operator who disables per-origin limits removes it. A crowd behind one address shares 16 MiB of fetches per minute, real-time delivery aside. `fetch_max_bytes` must stay at most the 4 MiB burst of the origin budget, otherwise every fetch is refused.

Every well-formed deposit counts against the deposit limit of its connection, accepted or not. Only accepted deposits count against the limits of the network origin and of the mailbox, and against byte budgets. A refused deposit, in particular one without a sufficient proof in pressure mode, therefore never consumes a budget shared with others. Otherwise one attacker behind a shared address (carrier-grade NAT, the Wi-Fi of a venue) could use up the budget of the whole crowd behind it for free, with deposits that cost them nothing.

Since deposits to unknown mailboxes are valid, the per-mailbox quota alone cannot protect the relay: a flooder spreads deposits over invented mailboxes. Byte budgets bound how fast one origin consumes storage. Without them, one address could fill a 1 GiB relay in about 20 minutes. With the defaults above, it needs more than three hours to reach the 80% threshold of section 9.3.

Many legitimate users can share one public address: carrier-grade NAT, public Wi-Fi, crowds at protests or festivals. Per-origin limits cannot tell such a crowd from an attacker, so they stay generous and an operator MAY disable them. Pressure mode is the real backstop, because it charges every deposit rather than every address.

### 9.3 Pressure mode and proof of work

When stored bytes cross a share of the storage cap, the relay enters pressure mode:

| Storage used | `pow_bits` | `max_ttl` for new deposits |
|---|---|---|
| below 80% | 0 (no proof required) | 7 days |
| from 80% | `B` | 24 hours |
| from 90% | `B + 1` | 24 hours |
| from 95% | `B + 2` | 24 hours |
| 100% | deposits refused with `relay_full`, and `full` is true | |

The shorter TTL makes storage drain faster. Envelopes already stored keep their expiration.

The base difficulty `B` is calibrated on the slowest phone the clients target: at the first threshold, a 1 KiB deposit MUST take at most 2 seconds at the 95th percentile on that phone, with the client implementation described below. Version 0 sets `B = 21`, measured on a Snapdragon 665 (Redmi Note 8T, 3.25 million hashes per second on its 8 cores): a mean of 0.65 s and a 95th percentile of 1.1 s for 1 KiB. An Apple A14 (iPhone 12 mini, 11.9 million hashes per second on its 6 cores) would allow `B = 23`. The A12, the oldest iPhone supported, is not measured yet. Pressure mode is the main defence against exhaustion: a few dozen network origins are enough to get around per-origin limits within minutes, so `B` must stay as high as the slowest targeted phone allows.

Pressure mode does not tell a flood from a genuine peak. During a large protest or a disaster, legitimate traffic alone can push a relay into pressure mode, and then every user pays the proof of work and gets the shorter expiration. Operators SHOULD set the storage cap well above the expected peak traffic. In the default memory-only mode the cap is RAM: a relay with a 1 GiB cap needs that much free memory, plus overhead.

A deposit in pressure mode requires `bits = pow_bits + log2(blob size / 1024)`, that is `pow_bits` for 1 KiB, `pow_bits + 2` for 4 KiB and `pow_bits + 4` for 16 KiB, so the cost grows with the size. The proof is made of 8 sub-proofs of `bits - 3` bits each. On average they cost the same work as one proof of `bits` bits, but the waiting time is far more predictable: found one after another, 8 sub-proofs take a time that follows an Erlang distribution, whose 95th percentile is 1.64 times the mean, against 3.0 times for a single proof. The calibration of `B` assumes this.

`pow` is 64 bytes: the 8 sub-proofs `pow_0` to `pow_7`, 8 bytes each, in order. The first byte of `pow_i` MUST equal `i`, which binds each sub-proof to its position; the other 7 bytes are free. Each sub-proof MUST satisfy: the first `bits - 3` bits (most significant bit first) of

```
SHA-256("cyclades/v0/pow" || nonce || mailbox_id || SHA-256(blob) || pow_i)
```

are zero, where `nonce` is the nonce of the connection. Proofs therefore cannot be computed before connecting nor reused on another connection. The hashed message is 119 bytes, two SHA-256 blocks, and its first 111 bytes are the same for every attempt. The relay verifies 8 hashes per deposit, remembers a 16-byte digest of each proof it accepted for the lifetime of the connection, and refuses a reused one. To bound that memory, it closes a connection once it has accepted 1000 proofs, with WebSocket close code 1000 (Normal Closure) rather than the 1013 of sections 7.6 and 9.4: this is a normal rotation to a new nonce, and the client reconnects to get one.

Clients SHOULD search the sub-proofs one after another, each with all cores at once, for example by splitting the 7 free bytes between threads. Searching them side by side, one core per sub-proof, makes the deposit wait for the slowest of 8 searches: at the same hash rate, the expected time grows by a factor of about 2.7.

A deposit without a sufficient proof gets `pow_required` with the number of `bits` needed. The client computes the proof and retries.

Since the cost grows with the size, a 16 KiB envelope at the first threshold takes about 10 seconds on average on the calibration phone, and 17 seconds at the 95th percentile. SHA-256 is cheap on graphics cards and dedicated hardware: this proof slows floods from ordinary machines and fleets of phones, not a well-equipped attacker. A memory-hard function is planned for a later version (section 14).

### 9.4 Connections

Every open connection costs the relay memory: about 270 KiB, measured, for one that holds a frame left unfinished and has joined two mailboxes. A relay MAY cap the connections it holds at once, in total and per network origin, and refuse the WebSocket upgrade beyond with HTTP status 403. A refused upgrade frees its place at once. These are operator values, set from the memory of the host: the reference relay, sized for a 512 MiB container, holds at most 400 connections, 64 per network origin. A per-origin cap also refuses, beyond it, the members of a crowd behind one address (carrier-grade NAT, the Wi-Fi of a venue).

A relay MAY also close a connection that completes no message for a minute, whatever bytes arrive. Without that, a frame left unfinished and fed one byte at a time keeps a connection and its buffers open for ever, since each byte resets the idle timeout of the transport. The reference relay checks every minute that at least one message has completed on the connection since the previous check. Otherwise it closes the connection with close code 1013, as in section 7.6, and at once: waiting for the client's close frame would hold it up to another minute. A client sends a heartbeat at least every 30 seconds (section 4).

A cap moves the cost of a flood of connections instead of removing it. Past it, new connections are refused for everyone until some close: an attacker with enough addresses can keep new clients out, but can no longer bring the relay down, which would lose every stored envelope. The real defence of a relay in service is more memory, then several relays (section 14).

## 10. Errors

Errors are channel replies with status `error` and the payload `{"reason": "<code>"}`. `pow_required` also carries `bits`. Error replies to `deposit` also carry the current `max_ttl` and `pow_bits` (section 6).

| Code | Meaning |
|---|---|
| `unsupported_protocol` | unknown protocol version |
| `invalid_payload` | malformed field, bad encoding or wrong length, payload that is not an object, unknown event |
| `unauthorized` | mailbox join refused |
| `invalid_size` | blob is not exactly one of the tiers |
| `mailbox_full` | mailbox quota reached |
| `relay_full` | relay storage cap reached |
| `rate_limited` | rate limit or byte budget exceeded |
| `pow_required` | pressure mode: proof of work missing, insufficient or reused |
| `too_many_mailboxes` | too many mailboxes joined on this connection |
| `mailbox_busy` | too many connections have joined this mailbox (section 7.2) |
| `not_allowed` | `ack` or `purge` on a group mailbox |

## 11. Requirements for relay implementations

### 11.1 Logs

- A relay MUST NOT write to logs or to disk any IP address, `mailbox_id`, public key, signature, nonce, envelope id, blob, topic name or payload parameter.
- Framework logging MUST be disabled for socket connections, channel joins, channel events and request parameters. Crash reports MUST NOT include payloads.
- A crash of the Erlang VM writes the state of every process to `erl_crash.dump`, and an operating-system core dump holds the whole memory. Relays MUST disable both: `ERL_CRASH_DUMP_BYTES=0` in the environment of the VM, and a core dump size of 0 for the relay process (`ulimit -c 0`, or `LimitCORE=0` under systemd).
- The reverse proxy in front of the relay is bound by the same rules: no access log with addresses or paths.

### 11.2 Client IP addresses

- The client address is read from `X-Forwarded-For` only when the TCP peer is one of the configured trusted proxies. Otherwise the TCP peer address is used.
- Several `X-Forwarded-For` lines form one list, in order. The client is the rightmost entry that is not a trusted proxy. If that entry is unreadable, the relay uses the TCP peer address: the entries further left were written by the client.
- The peer is compared with the trusted proxies after IPv4-mapped addresses are converted to IPv4, since a socket bound to `::` sees an IPv4 proxy as `::ffff:a.b.c.d`.
- Limits apply to the network origin: the IPv4 address, or the first 64 bits of an IPv6 address. IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) are treated as IPv4. Without this grouping, an attacker would change address at each connection within their own /64.
- A /64 is the smallest prefix usually assigned to one subscriber. An attacker holding a wider prefix (/56, /48) can still rotate, so an operator MAY group IPv6 origins by a wider prefix.
- The origin is used only in memory, for rate limiting, and is forgotten when the counter window expires. Hourly budgets keep a counter for up to about two hours. It is never logged.
- Rate limit counters SHOULD be keyed by a keyed hash of the origin, with a random key generated at boot.

### 11.3 Storage

- Memory-only is the default storage mode: envelopes are never written to persistent storage and are lost on restart. Persistent storage is an option for relays that must keep envelopes across restarts.
- In memory-only mode, a deleted envelope is not wiped from RAM: the Erlang VM frees memory without overwriting it. A memory dump of a running relay that is seized may therefore still contain envelopes that were acknowledged, purged or expired. This is accepted in version 0, since envelopes are encrypted end to end, but it means that deletion protects against reading the relay's state, not against forensic analysis of its memory.
- Memory-only storage holds only if memory stays in RAM. A host with swap can page envelopes out to disk, where they survive a restart and a power-off. Relays in memory-only mode MUST run without swap, or with swap encrypted under a key generated at boot and never stored.
- With persistent SQLite storage: `PRAGMA secure_delete = ON`, WAL mode, a `wal_checkpoint(TRUNCATE)` at least every minute and after each purge so that deleted envelopes do not linger in the WAL, and a bounded `journal_size_limit`.
- Backups MUST NOT include envelope storage. Only the relay configuration is backed up.

### 11.4 Surface

- No presence, no link previews, no content-dependent feature of any kind.
- A health endpoint MAY expose aggregate counters only (envelope count, stored bytes, open connections), never anything per mailbox. These counters SHOULD NOT be public: polled every second on a small relay, the number of open connections shows when someone connects. They belong to monitoring, on localhost or a private network. The public answer is only `{"status": "ok"}`.

## 12. Client guidance

- **Rotate mailboxes**: periodically, and immediately when a mailbox is flooded. Drain the old mailbox, purge it, then announce the new `mailbox_id` to contacts through end-to-end encrypted messages. Rotation costs the relay nothing because it keeps no registry.
- **Limit linkage**: joining several mailboxes on one connection links them for the relay. Use one mailbox per connection when that matters, or an anonymizing network.
- **Deposit on a separate connection**: never deposit to contacts on the connection that joins your own mailboxes. This also matters in pressure mode: a connection closes once it has accepted 1000 proofs (section 9.3), and with it every mailbox it had joined. If one connection joins mailbox M and deposits to mailboxes N1 to Nk, the relay learns that the owner of M writes to N1 to Nk, and can rebuild the social graph. Deposit connections SHOULD be short-lived. Both connections still share a network address unless an anonymizing network is used, and the delay between receiving and replying can correlate them.
- **Recompute joins after every reconnection**: the nonce changes, so a cached join payload will be refused.
- **Fetch after every join**: real-time delivery is best effort, and the relay closes a connection that does not keep up (section 7.6). After any closing, reconnect, join again, then fetch (from the expiration hour of the last envelope held, for a group mailbox).
- **Retry on `mailbox_busy`**: after a network change, the previous connections of a phone keep their places until the relay closes them, within 60 seconds. Retry the join after at least 5 seconds: each attempt uses a join from the budget of the connection (section 9.2).
- **Fit the pages to the link**: a client starts with a `limit` of 4. When its connection closes while it still awaits a fetch reply, it MUST halve its `limit` for the next fetches, down to 1. After 4 replies in a row received without a closing, it doubles it, up to `fetch_limit`. A client that keeps large pages on a slow link loops: a full page of 512 KiB takes about two minutes at 50 kbit/s, the relay closes the connection when the reply to the next heartbeat or push has waited 5 seconds behind it (section 7.6), and the client asks for the same page again.
- **Follow the state**: read it on joining `session`, in every deposit reply and in `state` events. When `full` is true, do not attempt a deposit: it would be refused, after the proof of work in pressure mode. Wait for a later `state`, or carry the message over the Bluetooth mesh.
- **Warn the user in pressure mode**: messages sent while it is active expire after `max_ttl` (24 hours by default) instead of 7 days, and sending takes longer because of the proof of work. Large content is better sent later, or over the Bluetooth mesh.
- **Pad before encrypting**: the ciphertext, headers and authentication tag included, must exactly match a tier. The padding scheme belongs to the client cryptography specification.
- **Acknowledge everything fetched** in a private mailbox, including envelopes that fail to decrypt, otherwise they use up the mailbox quota until they expire. Never acknowledge in a group mailbox.
- **One device per person** (`CLIENT-CRYPTO.md`, D2): a private mailbox is read from a single device, and an acknowledgement deletes the envelope for every connection. A group mailbox is read from the device of each member.
- **Read a group mailbox in order**: join it first, then fetch from the expiration hour of the last envelope held, until a full pass brings nothing new (section 7.3). A member away for more than 24 hours misses the group envelopes at the relay.
- **Large content**: split it into envelopes on the client side.
- **Do not trust the relay for time or ordering**: use timestamps and counters carried inside the encrypted payload.

## 13. Versioning

The protocol version is the integer sent when joining `session`. The domain separation strings contain the version (`v0`). Any incompatible change gets a new version number. A relay MAY support several versions at once.

## 14. Future work

- Federation: replication of envelopes between relays.
- Gateways connecting Bluetooth mesh islands through relays.
- Mailboxes without an addressed recipient, read by trial decryption.
- A memory-hard proof of work, replacing SHA-256 (section 9.3).
- Content-free push notifications (APNs), including an analysis of what device tokens let an operator link.
- Binary frames, to avoid the base64 overhead.

## 15. Test vectors

### 15.1 Valid join

Clients verify their implementation against these values. Ed25519 as computed here is deterministic. Implementations whose signatures are randomized (CryptoKit for example) produce different signature bytes; they MUST still verify `sig` below and their own signatures MUST be accepted by the relay.

```
seed       0101010101010101010101010101010101010101010101010101010101010101
pubkey     8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
pubkey64   iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w
mailbox_id d510051b943f9a47e4d98344ed8d415a5e2f372ffc99df72c37802d82545a6fb
mailbox64  1RAFG5Q_mkfk2YNE7Y1BWl4vNy_8md9yw3gC2CVFpvs
nonce      0202020202020202020202020202020202020202020202020202020202020202
nonce64    AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI
message    "cyclades/v0/join" || nonce || mailbox_id   (80 bytes)
sig        30cd15c6cccf7569be659770b879599aed0a02b186b7181faf90525cd4099fab
           df59f070a8fe396929d63080372417c5e8532c83f75b9b4be031e11b6529160c
sig64      MM0VxszPdWm-ZZdwuHlZmu0KArGGtxgfr5BSXNQJn6vfWfBwqP45aSnWMIA3JBfF6FMsg_dbm0vgMeEbZSkWDA
```

### 15.2 Rejected joins

Both signatures MUST be rejected by the checks of section 5.1. Used to join a mailbox, they get `unauthorized`.

N1, non-canonical `S`: same key, nonce and message as 15.1, with `S` replaced by `S + L`. Rejected by check 2.

```
sig_n1     30cd15c6cccf7569be659770b879599aed0a02b186b7181faf90525cd4099fab
           cc2de6cdc2614cc1ff722823161ef6d9e8532c83f75b9b4be031e11b6529161c
```

N2, small-order key: the public key is the identity point. With `R` the identity and `S = 0`, the verification equation holds for any message, so anyone can produce this signature. Rejected by check 4. Erlang/OTP 29 accepts it when the checks are skipped.

```
pubkey     0100000000000000000000000000000000000000000000000000000000000000
mailbox_id aaf0da62ad15838b0389a154dfeb2a307b2fcef106079214995c734655374713
nonce      same as 15.1
message    "cyclades/v0/join" || nonce || mailbox_id   (80 bytes)
sig_n2     0100000000000000000000000000000000000000000000000000000000000000
           0000000000000000000000000000000000000000000000000000000000000000
```

### 15.3 Proof of work

Test difficulty `bits = 11`, so each sub-proof needs 8 zero bits. Real deposits never use a difficulty this low; it only keeps the vectors short. Same nonce and `mailbox_id` as 15.1. Each `pow_i` below is the smallest value that works, counting up from `i || 00000000000000`.

```
blob        1024 bytes of 0x03
sha256blob  fcb424e6d90e2da82f75e861af6e631e7d6b39d84b956bb83791ec42cce9b422
pow         0000000000000054 010000000000002c 0200000000000125 03000000000000ca
            040000000000017d 0500000000000229 0600000000000010 07000000000001cb
pow64       AAAAAAAAAFQBAAAAAAAALAIAAAAAAAElAwAAAAAAAMoEAAAAAAABfQUAAAAAAAIpBgAAAAAAABAHAAAAAAAByw
hash_0      005a10b8df50c12e...   9 zero bits
hash_1      007fb39c0328dbc1...   9
hash_2      006be5a1c8048185...   9
hash_3      005950a855a6c466...   9
hash_4      004d0c2dbbe1db13...   9
hash_5      0047c2dd01c009b8...   9
hash_6      0013dd06ed046993...  11
hash_7      00e36fbf81b5764a...   8
```

Both of the following MUST be rejected:

- P1, insufficient: the same `pow` for a deposit that requires `bits = 12`. `hash_7` has only 8 zero bits, one short of the 9 required.
- P2, misplaced: the same `pow` with `pow_0` and `pow_1` swapped. Both hashes still start with 8 zero bits, but the first byte of each sub-proof no longer equals its position.

### 15.4 Group mailbox

Same key as 15.1.

```
pubkey            8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
group_mailbox_id  02dc045bb0b679e6cd81c92efb1125d24e57f9e8604b40a4e6634afd8f5d4b17
group64           AtwEW7C2eebNgcku-xEl0k5X-ehgS0Ck5mNK_Y9dSxc
```

## 16. Open points

Decided for version 0: expiration rounded to one hour, memory-only storage by default, 24-hour expiration in pressure mode, SHA-256 proof of work in 8 sub-proofs with `B = 21` (a memory-hard function comes in a later version), group mailboxes read without deletion and kept 24 hours (section 5.2).

1. **Default limits** (section 9): starting values, to be revisited after the first real deployments. `B = 21` is calibrated on a Snapdragon 665. It goes down if older phones are targeted, and is checked against the A12 once measured.
2. **Group mailboxes**: the relay sees the network addresses of the members who fetch them (section 2.2). Members who must hide it use an anonymizing network. Delivering one copy to each member's own mailbox would not hide it either: the relay would see bursts of deposits linking those mailboxes, and in pressure mode every member would cost a proof of work.
3. **Federation trust model**: which relays replicate to which, and what a replicating relay learns.
