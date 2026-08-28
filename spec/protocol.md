# Pilotfish protocol specification

Version 0.1. This document is normative. The Python implementation in
`pilotfish/protocol/` is tested against the vectors in `spec/vectors/`, not the
other way round.

## 1. Design constraints

A site being governed may lose contact with the authority for hours, and the
links it would use to restore contact are the ones under governance. Every part
of this protocol follows from that:

- Messages are one-directional and self-standing. There is no request/response
  pair anywhere in the protocol.
- Evidence and envelopes dated further into the future than a fixed skew
  allowance are refused. A clock running fast must not be able to make stale
  things look fresh.
- Authenticity is a property of the message, not of the channel. An envelope
  verifies alone, having arrived by any route, including one nobody designed.
- Nothing required for correct operation depends on reaching the authority.

## 2. Encoding

CBOR, canonical form: map keys sorted, integers in shortest form, no indefinite
length items.

A bundle hash is the SHA-256 of the bundle's canonical encoding. It must not be
computed from any runtime's object representation: a hash only one implementation
can reproduce is not part of a protocol. Timestamps on the wire are integer seconds since the Unix epoch,
UTC. Implementations must reject a message that does not decode to the exact
structure specified.

## 3. Envelope

Every message is carried in an envelope, encoded as a CBOR array of six elements
in this order:

| # | Field | Type |
|---|-------|------|
| 0 | `msg_type` | text string |
| 1 | `issuer` | text string |
| 2 | `issued_at` | unsigned integer, Unix seconds |
| 3 | `nonce` | byte string, exactly 16 bytes |
| 4 | `payload` | byte string |
| 5 | `signature` | byte string, 64 bytes |

Positional ordering is deliberate. Signed bytes must not be able to drift because
a field was renamed.

### 3.1 Signature

The signature is Ed25519 over the canonical CBOR encoding of the five-element
array `[msg_type, issuer, issued_at, nonce, payload]`, that is, the envelope
without its signature field.

Verification failure is an error, never a warning and never a boolean an
implementation can ignore. There is no unauthenticated mode and no bypass.

## 4. Messages

Five message types.

### 4.1 `POLICY_BUNDLE` (authority to site)

The signed rule set, carrying `authority_id`, a monotone `sequence` and its
validity window.

A site accepts it only if all of the following hold: the envelope issuer is the
authority this site answers to; the envelope is not stamped further into the
future than the skew allowance; the signature verifies under a trusted key; the
envelope nonce has not been seen before; the bundle names the same authority; the
sequence is strictly greater than any previously accepted; and the current time
is inside the validity window.

The sequence check is the one that is easy to leave out and expensive to omit.
Authenticity is not freshness. Without it, an old but validly signed bundle can
replace a newer and stricter one, widening the permitted set without anything
being forged, and every signature in the resulting audit trail still verifies.

A site that has no valid bundle does not fall back to the last one it liked. It
falls to its floor policy and marks every decision taken that way as degraded.

### 4.2 `OBSERVATION_BATCH` (site to authority)

Telemetry. Not required for operation. A site may drop these freely when its
uplink is expensive; the fact that a batch was dropped is itself recordable, and
a gap in the record is not an error.

### 4.3 `DECISION_RECEIPT` (site to authority)

One step in the life of a decision, hash-chained to the previous receipt from the
same site, with a contiguous sequence number. A verifier holding a run of
receipts can confirm that none were removed or reordered.

Each receipt carries a `kind`:

- `DECISION`: what was authorised.
- `EXECUTION`: what was attempted against the dataplane.
- `EFFECT`: what the dataplane was observed to hold afterwards, with an
  `outcome` of `ENFORCED`, `POSTCONDITION_FAILED` or `ENFORCEMENT_ERROR`, and a
  hash of the observed state.

Recording only the first is a distinct failure mode rather than a smaller
version of the same one: a site can report that a link was forbidden while that
link carried traffic all night, and its log verifies perfectly.

An agent resuming after a restart must recover its chain head from the existing
log. A chain that restarts at sequence 1 makes a restart indistinguishable from
somebody having deleted the middle of the log.

### 4.4 `FLOOR_CONFIG` (authority to site, at provisioning)

The degraded-mode policy, bound to one `site_id` and to a hash of that site's
link inventory. It is signed like everything else, because the floor is the mode
a site runs in exactly when nobody can reach it, which makes it the last thing
that should be whatever the local process happened to construct at start-up.

The floor may be more restrictive than ordinary policy. It must never be less:
it carries every constraint each traffic class declares, and adds its own refusal
of metered paths and free-space optics.

### 4.5 `AUTHORITY_DIRECTIVE` (authority to site)

A time-bounded override taking one link out, for a human who needs it gone now.
It is not policy and is deliberately carried separately, so that an exceptional
act reads as an exceptional act in the log rather than blending into a bundle
update.

## 5. Transport bindings

The normative binding is QUIC/HTTP3: each message is one request body with
content type `application/cbor`.

Any transport that can move an octet string is a valid degraded binding,
including a file on removable media. Since authenticity is a property of the
message, a degraded binding loses confidentiality and timeliness but not
correctness.

## 6. Test vectors

`spec/vectors/envelope.json` fixes a key, a nonce, a payload, the resulting
signing input, the signature and the encoded envelope. An implementation that
reproduces these bytes is wire-compatible.

The vectors are frozen. If a change makes them fail, the wire format changed, and
that is a breaking change for every party that has ever verified one of our
envelopes. Regenerating the file is not the remedy.
