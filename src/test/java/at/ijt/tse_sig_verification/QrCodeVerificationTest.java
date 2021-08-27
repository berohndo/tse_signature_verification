package at.ijt.tse_sig_verification;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class QrCodeVerificationTest {
    @Test
    public void testValidQrCode256() {
        QrCodeSignatureVerifier verifier = new QrCodeSignatureVerifier();

        boolean isValidSignature = verifier.verify(
                "V0;ERS 8cb8e2de-4052-481b-945b-118022951944;Kassenbeleg-V1;Beleg^21.42_0.00_0.00_0.00_0.00^21.42:Unbar;1;31;2021-08-23T14:36:27.000Z;2021-08-23T14:36:33.000Z;ecdsa-plain-SHA256;unixTime;TGnWiq3ZW7gi4Vs+DxLGsJZj9v271dHmhQAcb057F3oWkdKJ61UW2LLVTZQhW673yLa53Mm6oPeMU1Ns3ZOH7w==;BGFKQP7EENf3s5hTDXvlh+xyJ1Q9BNIa9LyYbYK+pTAKAGQ2fmI40p5QOrpHpvb+UuOrNQJdhzggHNfyyyDyf/g=");

        assertEquals(true, isValidSignature);
    }

    @Test
    public void testValidQrCode384() {
        QrCodeSignatureVerifier verifier = new QrCodeSignatureVerifier();

        boolean isValidSignature = verifier.verify(
                "V0;AMA-6200;KassenBeleg-V1;Beleg^2.90_0.00_0.00_0.00_2.10^5.00:Unbar;160504;344413;2021-07-23T10:12:54.000Z;2021-07-23T10:12:55.000Z;ecdsa-plain-SHA384;unixTime;NgqBkWMvhLmCKa9cJJ8JodfAdlkfcFFyW0J7Ks9lTz9I4QFKhLzyGF/02kWsCRg0LoiJtkq+0Ak9GovodNFLOBG00ewEj40/GbI9zLtNt9j90w4Sz3GcxTSrr3rqhIhN;BCd1vZvSJsJwBTqshgDVsrG4Gg+oN3jeeFEgjGiKs9ELd170vy/jO3iMMF6tAVUfjyYn9jRXng8Z4qWXaqoJ53+y+OFeSY/lQsdZWCODkzhlhkJxJw2k9Z1A4gFX6Riotw==");

        assertEquals(true, isValidSignature);
    }
}
