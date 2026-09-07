use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use std::sync::Arc;
use rustls::RootCertStore;
use rustls::pki_types::TrustAnchor;
use webpki::{EndEntityCert, KeyUsage};

#[derive(Debug)]
pub struct NoHostnameVerifier {
    pub inner: Arc<dyn ServerCertVerifier>,
    pub roots: Arc<RootCertStore>,
}

impl NoHostnameVerifier {
    pub fn new(roots: Arc<RootCertStore>) -> Result<Self, Error> {
        let inner = rustls::client::WebPkiServerVerifier::builder(roots.clone())
            .build()
            .map_err(|e| Error::General(e.to_string()))?;
        Ok(Self { inner, roots })
    }
}

impl ServerCertVerifier for NoHostnameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = EndEntityCert::try_from(end_entity)
            .map_err(|e| Error::General(format!("{:?}", e)))?;
            
        let trust_anchors: Vec<TrustAnchor> = self.roots.roots.iter().map(|ta| {
            TrustAnchor {
                subject: ta.subject.clone(),
                subject_public_key_info: ta.subject_public_key_info.clone(),
                name_constraints: ta.name_constraints.clone(),
            }
        }).collect();

        // Use the provider's algorithms
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        
        cert.verify_for_usage(
            provider.signature_verification_algorithms.all,
            &trust_anchors,
            intermediates,
            now,
            KeyUsage::server_auth(),
            None,
            None,
        ).map_err(|e| Error::General(format!("{:?}", e)))?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
