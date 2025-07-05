# Wycheproof test drivers for Mbed TLS

As part of the Mbed TLS 3.6.2 security audit, Calif developed Wycheproof test drivers for RSA and ECDSA, focusing on key functionalities such as decryption/encryption and signature verification. The test vectors used in these tests are sourced from [Wycheproof Test Vectors](https://github.com/C2SP/wycheproof/tree/master/testvectors).

Below are the specific tests and their corresponding functions used for RSA and ECDSA.

## RSA Tests

* [PKCS#1 v2.1 RSAES-PKCS1-V1_5-DECRYPT](rsaes-pkcs1-v1_5-decrypt-test.c): Test the decryption functionality using the RSA PKCS#1 v1.5 standard.

* [PKCS#1 v2.1 RSAES-OAEP-DECRYPT](rsaes-oaep-decrypt-test.c): Test the decryption functionality using the RSA Optimal Asymmetric Encryption Padding (OAEP) scheme.

* [PKCS#1 v2.1 RSASSA-PKCS1-v1_5-VERIFY](rsassa-pkcs1-v1_5-verify-test.c): Verify digital signatures using the RSA PKCS#1 v1.5 standard.

* [PKCS#1 v2.1 RSASSA-PSS-VERIFY](rsassa-pss-verify-test.c): Verify digital signatures using the RSA Probabilistic Signature Scheme (PSS).

## ECDSA Tests

* [Verify an ECDSA signature using the P1316 standard](ecdsa-verify-p1316-test.c)

* [Verify an ECDSA signature encoded in DER format](ecdsa-verify-der-test.c)
