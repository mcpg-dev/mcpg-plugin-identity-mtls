# mTLS Identity Resolver (header-injection) — `dev.mcpg.identity.mtls`

> class `identity_provider` · `native` · package `mcpg-plugin-identity-mtls` · artifact `libmcpg_plugin_identity_mtls.so` · Apache-2.0

Turns the client-certificate details that a TLS terminator forwards in HTTP
headers into a gateway caller identity. When an Envoy or Istio sidecar, an nginx
front end, or a cloud load balancer terminates mutual TLS on the gateway's behalf,
it injects the peer certificate's subject or fingerprint into a header; this
plugin parses that header, canonicalises a subject out of it, and attaches the
roles, groups, scopes, and attributes you map to that subject. It reads headers
only — it does not itself inspect or validate a peer certificate — and performs
no outbound network calls. Reach for it when workload identity in your mesh is
already carried by client certificates and you want the gateway to honour it.

## What it does
- Walks the configured `sources` in order and resolves on the first one a subject
  can be extracted from, so you can accept several proxy shapes at once.
- Parses Envoy and Istio `X-Forwarded-Client-Cert` values, splitting chain hops on
  commas that fall outside quoted runs — a DN containing its own commas stays
  intact — and reads the `Subject` and `Hash` keys from the selected hop.
- Accepts nginx-style single-DN headers and arbitrary cloud load-balancer headers
  carrying either a DN or a SHA-256 fingerprint.
- Canonicalises the subject three ways: the first `CN=` value, the whole
  whitespace-normalised DN, or a 64-character SHA-256 fingerprint with any
  separators stripped.
- Stamps `mtls.source` on the resolved identity's attributes, plus
  `mtls.subject_dn` and `mtls.fingerprint` when the source provided them.
- Declares no required capabilities: it never opens a socket or reads a file.

## Configuration
Loaded from the flat top-level `plugins:` list; every `identity_provider` entry
joins the gateway's identity chain in declaration order.

```yaml
plugins:
  - id: dev.mcpg.identity.mtls
    class: identity_provider
    source: { path: ./plugins/libmcpg_plugin_identity_mtls.so }
    config:
      sources:
        - { kind: xfcc, header: X-Forwarded-Client-Cert, chain_position: first }
        - { kind: dn_string, header: X-SSL-Client-S-DN }
        - { kind: custom_header, header: X-Client-Fingerprint, extraction_hint: fingerprint }
      extraction:
        mode: subject_cn
        case_sensitive: false
      identities:
        orders-svc:                     # keyed by the canonicalised subject
          roles: ["service"]
          scopes: ["orders.read"]
          attributes: { tenant: acme }
      resolution:
        trust_level: verified           # opt-in; see Security below
        auth_provider_label: mtls
```

| Field | Type | Default | Description |
|---|---|---|---|
| `sources` | source[] | — (required) | Header sources in priority order; must be non-empty, and each must name a header. |
| `extraction.mode` | `subject_cn` \| `subject_dn` \| `fingerprint` | — (required) | How the subject is derived from the parsed metadata. |
| `extraction.case_sensitive` | bool | `false` | Applies to `subject_cn`; when `false` the CN is lowercased. |
| `identities` | map<string, metadata> | `{}` | Per-subject `roles`, `groups`, `scopes`, and `attributes`, keyed by the canonicalised subject. |
| `resolution.trust_level` | `verified` \| `header_asserted` | `header_asserted` | Trust level stamped on a resolved identity. |
| `resolution.auth_provider_label` | string | `mtls` | `auth_provider` value on the resolved identity. |

Each entry in `sources` is one of:

| `kind` | Fields | Reads |
|---|---|---|
| `xfcc` | `header`, `chain_position` (`first` \| `last`, default `first`) | An Envoy/Istio `X-Forwarded-Client-Cert` chain; `chain_position` picks which hop to trust. |
| `dn_string` | `header` | A single subject DN, the nginx `X-SSL-Client-S-DN` shape. |
| `custom_header` | `header`, `extraction_hint` (`dn` \| `fingerprint`) | Any operator- or cloud-named header, interpreted per the hint. |

Unknown fields are rejected. A configuration that fails validation aborts the
plugin's registration rather than loading an identity resolver with holes in it.

## Security
Everything this plugin reads arrives in a request header, and a header can be
forged by anyone who can reach the gateway directly. That is why
`resolution.trust_level` defaults to the lower `header_asserted` tier. Raise it
to `verified` only when both of these hold:

- a trusted proxy terminates mutual TLS in front of the gateway, and
- that proxy strips any inbound copy of the configured headers before injecting
  its own.

Without both, a client could assert an arbitrary subject as a fully trusted
principal. For the same reason, prefer `chain_position: first` when your proxy
puts the directly-connected peer first in the XFCC chain, and make sure no
untrusted hop can prepend to it.

Resolution produces one of three outcomes, and the difference matters for how the
identity chain proceeds:

- **Resolved** — a source yielded a subject. The chain stops and the identity is
  used, with metadata from `identities` when the subject has an entry there.
- **None** — no configured source produced any certificate metadata. The chain
  falls through to the next identity provider.
- **Invalid** — a source produced metadata but no subject could be extracted from
  it: no `CN=` in the DN, an empty CN, or a fingerprint that is not 64 hex
  characters. **The chain stops here** and the request is refused, rather than
  falling through to a laxer provider.

A subject with no entry in `identities` still resolves — it simply carries no
roles, groups, or scopes. Use a policy rule if unmapped subjects should be
refused outright.

## Observability
- `mcpg_identity_mtls_resolutions_total{outcome}` — counted per resolution, with
  `outcome` one of `resolved`, `none`, or `invalid`.
- `mcpg_identity_mtls_resolve_ms` — resolution latency.

## Build
`cdylib-export` is enabled by default, so the plain build already produces the
loadable artifact. Disable the default features when linking this crate as an
rlib path dependency alongside other plugins, so the build does not emit two
`mcpg_plugin_register` exports.

```bash
cargo build -p mcpg-plugin-identity-mtls --features cdylib-export --release   # → target/release/libmcpg_plugin_identity_mtls.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Identity and authorization in the gateway: <https://mcpg.dev/docs/security/identity-and-authorization>
- Plugin classes and the ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Sibling resolvers: `libs/plugins/identity/workload`, `libs/plugins/identity/oidc`,
  `libs/plugins/identity/basic`
