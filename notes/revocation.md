## Authorization-Bound Revocation

ACE-GF enables immediate and intrinsic revocation through
authorization-bound revocation. Revocation is achieved by rendering the
REV mathematically unreachable rather than by relying on external
revocation infrastructure.

In high-security deployments, the Authorization Pipeline MAY be
distributed across multiple components, such as a user-held credential
combined with a server-held secret or policy-controlled input.

Revocation may be performed using one or more of the following actions:

1. **Revocation by Destruction**: Destroying the associated Sealed
   Artifact (SA).
2. **Credential Component Removal**: Removing or invalidating a required
   authorization input (e.g., server-held secret or credential factor).

Once revocation has occurred, reconstruction of the REV becomes
cryptographically infeasible. As a result:

- No derived keys can be regenerated.
- No partial identity state is exposed.
- No external revocation mechanisms (such as CRLs or OCSP) are required.

The identity remains offline until valid authorization inputs are
restored, such as by deploying a backup SA under the control of the
authorizing entity.
