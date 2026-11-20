# Suite bill of materials fixture

Produced once with `cosign` v2.4.1 and a throwaway key pair, offline:

```sh
cosign generate-key-pair
cosign sign-blob --key cosign.key --tlog-upload=false --yes \
    --output-signature suite-1.10.0.yaml.sig suite-1.10.0.yaml
```

`release.pub` is the public half (`cosign.pub`). The private key was deleted
right after signing; it is not needed to verify. `tools/tests/test_suite.py`
checks that `papaia-ctl suite verify` accepts this real `cosign sign-blob`
output. Do not edit `suite-1.10.0.yaml`: any change breaks the signature.
