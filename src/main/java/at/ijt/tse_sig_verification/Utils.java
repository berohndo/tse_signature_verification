package at.ijt.tse_sig_verification;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.util.Base64;

public class Utils {
    public static long convertISO8601DateStringToUnixTime(String dateString) {
        TemporalAccessor ta = DateTimeFormatter.ISO_INSTANT.parse(dateString);
        Instant i = Instant.from(ta);

        return i.getEpochSecond();
    }

    public static byte[] decodeBase64(String base64Data) {
        return Base64.getDecoder().decode(base64Data);
    }

    public static byte[] decodeBase64AndSha256(String base64Data) throws NoSuchAlgorithmException {
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        d.update(decodeBase64(base64Data));
        return d.digest();
    }
}
