//! Managed Proxy backend TLS has an observability boundary. Native server-side
//! encryption is a selected fact; neither it, RequireTLS, nor a direct-to-DB
//! certificate probe proves the proxy's CA/hostname verification of that session.
use crate::core::{evidence::*, state::StateValue};
pub(super) fn attach(
    claim: &mut ObservationClaim,
    assurance: &mut ClaimAssurance,
    encrypted: Option<bool>,
    proof: &str,
    contract: Option<BackendTlsTrustContract>,
) {
    if claim.address.effect
        != (EffectKindV2::Transport {
            segment: TransportSegment::NativeRouteToDatabase,
        })
    {
        return;
    }
    claim.transport = vec![TransportFact {
        validation_basis: contract,
        segment: TransportSegment::NativeRouteToDatabase,
        encrypted,
        ca_verified: None,
        hostname_verified: None,
        ipc_boundary_verified: None,
        evidence_refs: vec![proof.into()],
    }];
    if contract == Some(BackendTlsTrustContract::AwsRdsProxyManagedEncryptionV1)
        && encrypted == Some(true)
    {
        // The caller has established the current native target binding and a
        // CA/hostname-verified client channel. Internal verification stays None.
        claim.observed = StateValue::Present;
        assurance.coverage.transport = Assurance::Verified {
            evidence_refs: vec![proof.into()],
        };
        return;
    }
    claim.observed = StateValue::Unknown;
    assurance.coverage.transport = if contract.is_some() {
        Assurance::Unconfirmed {
            reason: EvidenceReason::TransportUnconfirmed,
        }
    } else {
        Assurance::Unsupported {
            reason: EvidenceReason::ProviderManagedTlsValidationUnobservable,
        }
    };
    assurance.coverage.completeness = Assurance::Unconfirmed {
        reason: EvidenceReason::TransportUnconfirmed,
    };
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backend_encryption_is_preserved_without_fabricating_ca_or_hostname() {
        for ssl in [None, Some(false), Some(true)] {
            let (mut i, _, mut raw) = super::super::aws_postgres::tests::sample();
            i.request.cases[0].kind = FixedObservationCase::Transport;
            i.request.cases[0].address.effect = EffectKindV2::Transport {
                segment: TransportSegment::NativeRouteToDatabase,
            };
            // Modify the selected server observation, never a verification flag.
            super::super::aws_postgres::set_backend_ssl_for_test(&mut raw, ssl);
            let (claim, a) = super::super::aws_postgres::normalize(
                &i,
                &i.request.cases[0],
                111,
                114,
                &raw,
                "proof",
            )
            .unwrap();
            assert_eq!(claim.observed, StateValue::Unknown);
            assert_eq!(claim.transport[0].encrypted, ssl);
            assert_eq!(claim.transport[0].ca_verified, None);
            assert_eq!(claim.transport[0].hostname_verified, None);
            assert_eq!(
                a.coverage.transport,
                Assurance::Unsupported {
                    reason: EvidenceReason::ProviderManagedTlsValidationUnobservable
                }
            );
        }
    }
}

#[cfg(test)]
mod managed_tests {
    use super::*;
    #[test]
    fn pg_explicit_contract_keeps_ca_hostname_unknown_and_requires_backend_ssl() {
        for ssl in [None, Some(false), Some(true)] {
            let (mut i, _, mut raw) = super::super::aws_postgres::tests::sample();
            let c = &mut i.request.cases[0];
            c.kind = FixedObservationCase::Transport;
            c.address.effect = EffectKindV2::Transport {
                segment: TransportSegment::NativeRouteToDatabase,
            };
            c.backend_tls_trust = Some(BackendTlsTrustContract::AwsRdsProxyManagedEncryptionV1);
            super::super::aws_postgres::set_backend_ssl_for_test(&mut raw, ssl);
            let (claim, assurance) = super::super::aws_postgres::normalize(
                &i,
                &i.request.cases[0],
                111,
                114,
                &raw,
                "proof",
            )
            .unwrap();
            assert_eq!(
                claim.observed,
                if ssl == Some(true) {
                    StateValue::Present
                } else {
                    StateValue::Unknown
                }
            );
            assert_eq!(claim.transport[0].ca_verified, None);
            assert_eq!(claim.transport[0].hostname_verified, None);
            assert_eq!(
                claim.transport[0].validation_basis,
                i.request.cases[0].backend_tls_trust
            );
            assert_eq!(
                matches!(assurance.coverage.transport, Assurance::Verified { .. }),
                ssl == Some(true)
            );
        }
    }
}
