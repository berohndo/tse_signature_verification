package at.ijt.tse_sig_verification;

import static org.junit.Assert.assertEquals;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.ZoneId;
import java.util.TimeZone;

import org.junit.Test;

public class UtilsTest {
    @Test
    public void testConvertQrCodeDateToUnixTime() throws ParseException {
        assertEquals(1629729393, Utils.convertISO8601DateStringToUnixTime("2021-08-23T14:36:33.000Z"));
    }

    @Test
    public void testConvertQrCodeDateToDate() throws ParseException {
        SimpleDateFormat df = new SimpleDateFormat("dd.MM.yyyy hh:mm:ss");
        df.setTimeZone(TimeZone.getTimeZone("Etc/UTC"));

        assertEquals(df.parse("23.08.2021 14:36:33"), Utils.convertISO8601DateStringToDate("2021-08-23T14:36:33.000Z"));
    }
}
