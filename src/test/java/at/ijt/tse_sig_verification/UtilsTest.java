package at.ijt.tse_sig_verification;

import static org.junit.Assert.assertEquals;

import java.text.ParseException;

import org.junit.Test;

public class UtilsTest {

    @Test
    public void testConvertQrCodeDateToUnixTime() throws ParseException {
        assertEquals(1629729393, Utils.convertISO8601DateStringToUnixTime("2021-08-23T14:36:33.000Z"));
    }
}
