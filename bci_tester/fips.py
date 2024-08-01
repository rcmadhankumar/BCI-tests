"""Module containing utility functions & constants for FIPS compliant digests."""

import os

from bci_tester.data import OS_VERSION

#: openssl digests that are not FIPS compliant
NONFIPS_DIGESTS = ("blake2b512", "blake2s256", "md5", "rmd160", "sm3")

# OpenSSL 3.x in Tumbleweed dropped those as they're beyond deprecated
if OS_VERSION not in ("basalt", "tumbleweed", "15.6"):
    NONFIPS_DIGESTS += ("md4", "mdc2")

#: FIPS compliant openssl digests
FIPS_DIGESTS = (
    "sha1",
    "sha224",
    "sha256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "sha384",
    "sha512",
    "sha512-224",
    "sha512-256",
    "shake128",
    "shake256",
)


#: all digests supported by openssl
ALL_DIGESTS = NONFIPS_DIGESTS + FIPS_DIGESTS

assert len(set(ALL_DIGESTS)) == len(ALL_DIGESTS)

#: gnutls digests that are not FIPS compliant
NONFIPS_DIGESTS_GNUTLS = ("md5", "gostr341194", "streebog-256", "streebog-512")

#: gnutls digests that are FIPS compliant 
FIPS_DIGESTS_GNUTLS = (
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
)

#: all digests supported by gnutls
ALL_DIGESTS_GNUTLS = NONFIPS_DIGESTS_GNUTLS + FIPS_DIGESTS_GNUTLS

assert len(set(ALL_DIGESTS_GNUTLS)) == len(ALL_DIGESTS_GNUTLS)

def host_fips_supported(
    fipsfile: str = "/proc/sys/crypto/fips_enabled",
) -> bool:
    """Returns a boolean whether FIPS mode is supported on this machine.

    Parameters:
    fipsfile: path to the file in :file:`/proc` determining whether FIPS mode is enabled

    """
    return os.path.exists(fipsfile)


def host_fips_enabled(fipsfile: str = "/proc/sys/crypto/fips_enabled") -> bool:
    """Returns a boolean indicating whether FIPS mode is enabled on this
    machine.

    Parameters:
    fipsfile: path to the file in :file:`/proc` determining whether FIPS mode is enabled

    """
    if not host_fips_supported(fipsfile):
        return False

    with open(fipsfile, encoding="utf8") as fipsfile_fd:
        return fipsfile_fd.read().strip() == "1"


def target_fips_enforced() -> bool:
    """Returns a boolean indicating whether FIPS mode is enforced on this target."""
    return os.getenv("TARGET", "obs") in ("dso",)
