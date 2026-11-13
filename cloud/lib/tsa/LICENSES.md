# Licenses of the dependencies of lib/tsa

| package | used for | license | checked |
|---|---|---|---|
| asn1crypto 1.5.1 | DER of TimeStampReq/TimeStampResp/CMS (tsa.py, testtsa.py) | MIT | `pip show asn1crypto` in server/.venv |
| cryptography 50.0.2 | signature (RSA PKCS#1 v1.5 / PSS, ECDSA) and X.509 chain | Apache-2.0 OR BSD-3-Clause | `pip show cryptography` |
| Python stdlib (urllib, http.server) | HTTP POST of the query; test TSA server | PSF | - |

Both are permissive. asn1crypto is NOT yet in `deploy/requirements.txt` (owned by 07/01): it has to be added there for the server image,
and the evidence-pack checker needs it only when the pack holds `.tsr` files (otherwise the TSA line says "not checked").
