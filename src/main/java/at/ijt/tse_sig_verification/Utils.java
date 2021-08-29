package at.ijt.tse_sig_verification;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.util.Base64;
import java.util.Date;

public class Utils {
    public static long convertISO8601DateStringToUnixTime(String dateTimeString) {
        TemporalAccessor ta = DateTimeFormatter.ISO_INSTANT.parse(dateTimeString);
        Instant i = Instant.from(ta);

        return i.getEpochSecond();
    }

    public static Date convertISO8601DateStringToDate(String dateTimeString) {
        TemporalAccessor ta = DateTimeFormatter.ISO_INSTANT.parse(dateTimeString);
        Instant i = Instant.from(ta);

        return Date.from(i);
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
