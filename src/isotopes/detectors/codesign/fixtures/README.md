These are disposable self-signed public certificates generated for metadata-only
unit tests. They contain Code Signing EKU, Client Authentication EKU, or no EKU,
respectively. No private keys are committed or retained. Tests do not evaluate
certificate trust or dates and do not import them into a Keychain.

Generate an equivalent fixture with `/usr/bin/openssl req -new -x509 -newkey
rsa:2048 -nodes -days 1 -config fixture.cnf -outform DER -out fixture.cer
-keyout disposable.pem`, using an `[ext]` section containing
`extendedKeyUsage=codeSigning`, `extendedKeyUsage=clientAuth`, or
`keyUsage=digitalSignature`. Delete the disposable private key afterward.
