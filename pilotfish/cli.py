"""Command line entry points for the authority side."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from pilotfish.authority.signer import BundleSigner, load_bundle_json
from pilotfish.protocol.envelope import SignatureInvalid, decode_envelope, verify
from pilotfish.protocol.messages import decode_bundle


def _read_private_key(path: Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(path.read_text().strip()))


def _read_public_key(path: Path) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(path.read_text().strip()))


def _sign_bundle(args: argparse.Namespace) -> int:
    bundle = load_bundle_json(args.policy, now=datetime.now(tz=UTC))
    blob = BundleSigner(_read_private_key(Path(args.key)), args.issuer).publish(
        bundle, now=datetime.now(tz=UTC)
    )
    Path(args.out).write_bytes(blob)
    print(f"signed bundle {bundle.bundle_id} ({bundle.hash()[:16]}) to {args.out}")
    return 0


def _verify_bundle(args: argparse.Namespace) -> int:
    envelope = decode_envelope(Path(args.file).read_bytes())
    try:
        verify(envelope, _read_public_key(Path(args.key)))
    except SignatureInvalid as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    bundle = decode_bundle(envelope.payload)
    print(f"verified bundle {bundle.bundle_id} from {envelope.issuer}")
    print(f"  hash        {bundle.hash()}")
    print(f"  valid until {bundle.not_after.isoformat()}")
    print(f"  links       {', '.join(link.id for link in bundle.links)}")
    print(f"  classes     {', '.join(c.id for c in bundle.traffic_classes)}")
    print(f"  rules       {len(bundle.rules)}")
    return 0


def _keygen(args: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization

    key = Ed25519PrivateKey.generate()
    private_hex = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public_hex = (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    Path(args.out).write_text(private_hex + "\n")
    Path(args.out + ".pub").write_text(public_hex + "\n")
    print(f"wrote {args.out} and {args.out}.pub")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pilotfish", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate an Ed25519 authority key pair")
    keygen.add_argument("--out", required=True)
    keygen.set_defaults(func=_keygen)

    signer = sub.add_parser("sign-bundle", help="sign a policy file into a bundle envelope")
    signer.add_argument("policy")
    signer.add_argument("--key", required=True)
    signer.add_argument("--issuer", default="authority-1")
    signer.add_argument("--out", required=True)
    signer.set_defaults(func=_sign_bundle)

    verifier = sub.add_parser("verify-bundle", help="verify and describe a bundle envelope")
    verifier.add_argument("file")
    verifier.add_argument("--key", required=True)
    verifier.set_defaults(func=_verify_bundle)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
