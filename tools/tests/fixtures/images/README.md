# Image signature fixture

Real output of `cosign sign` (cosign v2.4.1) on an image in a local
`registry:2`, with a throwaway key pair and without a transparency log:

```sh
cosign generate-key-pair
cosign sign --key cosign.key --tlog-upload=false --allow-http-registry --yes \
    registry:5000/test/busybox@sha256:d82c2ab94640ded77cf76514ce6a84870761105058a4a9e51b05a8a79be97a6c
```

cosign stores the signature as an OCI manifest under the tag
`sha256-<hex>.sig` of the same repository. Captured from the registry:

- `signature-manifest.json`: that manifest; its one layer has the media type
  `application/vnd.dev.cosign.simplesigning.v1+json` and carries the base64
  signature in the annotation `dev.cosignproject.cosign/signature`;
- `payload.json`: the layer blob (simple signing payload) naming the signed
  manifest digest;
- `cosign.pub`: the public half of the key pair. The private key was deleted
  right after signing.

`tools/tests/test_images.py` serves these files from a fake registry and
checks that `lib/images.py` accepts them. Do not edit them: any change breaks
the signature.
