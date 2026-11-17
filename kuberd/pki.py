import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from kuberd.constants import (
    CA_VALIDITY,
    CLOCK_SKEW,
    SA_KEY_SIZE,
)
from kuberd.utils import (
    KeyCert,
    new_key,
    x509_name,
    key_usage,
    sign_leaf,
)


# --- PEM helpers -------------------------------------------------------------


def cert_to_pem(cert: x509.Certificate) -> bytes:
    """Encode a certificate as PEM."""
    return cert.public_bytes(serialization.Encoding.PEM)


def key_to_pem(key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey) -> bytes:
    """Encode a private key as PEM."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_key_to_pem(key: rsa.RSAPrivateKey) -> bytes:
    """Encode a public key as PEM."""
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# --- Public API --------------------------------------------------------------


def generate_ca(common_name: str) -> KeyCert:
    """Generate a self-signed CA."""
    key = new_key()
    name = x509_name(common_name)
    now = datetime.datetime.now(datetime.timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - CLOCK_SKEW)
        .not_valid_after(now + CA_VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(key_usage(digital_signature=True, cert_sign=True), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return KeyCert(key, cert)


def generate_server_cert(
    ca: KeyCert, common_name: str, sans: list[str], *, client_auth: bool = False
) -> KeyCert:
    """Generate a server certificate."""
    usages = [ExtendedKeyUsageOID.SERVER_AUTH]
    if client_auth:
        usages.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    return sign_leaf(ca, x509_name(common_name), usages, sans)


def generate_client_cert(
    ca: KeyCert, common_name: str, organizations: list[str] | tuple[str, ...] = ()
) -> KeyCert:
    """Generate a client certificate."""
    return sign_leaf(ca, x509_name(common_name, organizations), [ExtendedKeyUsageOID.CLIENT_AUTH])


def generate_service_account_key() -> rsa.RSAPrivateKey:
    """Generate the ServiceAccount signing key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=SA_KEY_SIZE)
