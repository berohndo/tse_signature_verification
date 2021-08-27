# tse_signature_verification

Java sample program to verify a TSE/DSFinV-K signature.

Takes a qr code string like:

`V0;ERS 8cb8e2de-4052-481b-945b-118022951944;Kassenbeleg-V1;Beleg^21.42_0.00_0.00_0.00_0.00^21.42:Unbar;1;31;2021-08-23T14:36:27.000Z;2021-08-23T14:36:33.000Z;ecdsa-plain-SHA256;unixTime;TGnWiq3ZW7gi4Vs+DxLGsJZj9v271dHmhQAcb057F3oWkdKJ61UW2LLVTZQhW673yLa53Mm6oPeMU1Ns3ZOH7w==;BGFKQP7EENf3s5hTDXvlh+xyJ1Q9BNIa9LyYbYK+pTAKAGQ2fmI40p5QOrpHpvb+UuOrNQJdhzggHNfyyyDyf/g=`

and verifies the included signature.

### Limitations

- only supports `ecdsa-plain-SHA256` and `ecdsa-plain-SHA384`
- only supports `unixTime`
