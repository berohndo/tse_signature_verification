package at.ijt.tse_sig_verification;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public class App {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
            InvalidKeyException, SignatureException {

        System.out.println(new QrCodeSignatureVerifier().verify(
                "V0;ERS 8cb8e2de-4052-481b-945b-118022951944;Kassenbeleg-V1;Beleg^21.42_0.00_0.00_0.00_0.00^21.42:Unbar;1;31;2021-08-23T14:36:27.000Z;2021-08-23T14:36:33.000Z;ecdsa-plain-SHA256;unixTime;TGnWiq3ZW7gi4Vs+DxLGsJZj9v271dHmhQAcb057F3oWkdKJ61UW2LLVTZQhW673yLa53Mm6oPeMU1Ns3ZOH7w==;BGFKQP7EENf3s5hTDXvlh+xyJ1Q9BNIa9LyYbYK+pTAKAGQ2fmI40p5QOrpHpvb+UuOrNQJdhzggHNfyyyDyf/g="));
    }

}
