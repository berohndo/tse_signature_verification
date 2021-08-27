package at.ijt.tse_sig_verification;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DERTaggedObject;

public class QrCodeSignatureVerifier {
    public boolean verify(String qrCodeString) {
        try {
            byte[] rawdata = createRawDataFromQrCode(qrCodeString);
            byte[] signature = createDerSignatureFromQrCode(qrCodeString);
            PublicKey publicKey = createPublicKeyFromQrCode(qrCodeString);

            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(rawdata);

            return ecdsaVerify.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private PublicKey createPublicKeyFromQrCode(String qrCodeString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        String[] parts = qrCodeString.split(";");
        byte[] plainPublicKey = Utils.decodeBase64(parts[11]);

        return generateP256PublicKeyFromPlain(plainPublicKey);
    }

    private byte[] createDerSignatureFromQrCode(String qrCodeString) throws IOException {
        String[] parts = qrCodeString.split(";");
        String signature = parts[10];
        byte[] plainSignature = Utils.decodeBase64(signature);

        return convertPlainToDEREncodedSignature(plainSignature);
    }

    private byte[] createRawDataFromQrCode(String qrCodeString) throws IOException, NoSuchAlgorithmException {
        String[] parts = qrCodeString.split(";");

        long version = 2;
        String certifiedDataType = "0.4.0.127.0.7.3.7.1.1";
        String operationType = "FinishTransaction";
        String clientId = parts[1];
        String processType = parts[2];
        String processData = parts[3];
        String transactionNumber = parts[4];
        String signatureAlgorithm = mapSignatureAlgorithmToOid(parts[8]);
        long signatureCounter = Long.parseLong(parts[5]);
        long logTime = Utils.convertISO8601DateStringToUnixTime(parts[7]);
        byte[] serialNumber = Utils.decodeBase64AndSha256(parts[11]);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ASN1OutputStream dos = ASN1OutputStream.create(baos);

        dos.writeObject(new ASN1Integer(version));
        dos.writeObject(new ASN1ObjectIdentifier(certifiedDataType));
        dos.writeObject(new DERTaggedObject(false, 0, new DEROctetString(operationType.getBytes())));
        dos.writeObject(new DERTaggedObject(false, 1, new DEROctetString(clientId.getBytes())));
        dos.writeObject(new DERTaggedObject(false, 2, new DEROctetString(processData.getBytes())));
        dos.writeObject(new DERTaggedObject(false, 3, new DEROctetString(processType.getBytes())));
        dos.writeObject(
                new DERTaggedObject(false, 5, new DEROctetString(new BigInteger(transactionNumber).toByteArray())));
        dos.writeObject(new DEROctetString(serialNumber));

        dos.writeObject(new DERSequence(new ASN1ObjectIdentifier(signatureAlgorithm)));
        dos.writeObject(new ASN1Integer(signatureCounter));
        dos.writeObject(new ASN1Integer(logTime));

        dos.close();

        return baos.toByteArray();
    }

    private String mapSignatureAlgorithmToOid(String signatureAlgorithm) {
        if ("ecdsa-plain-SHA256".equals(signatureAlgorithm)) {
            return "0.4.0.127.0.7.1.1.4.1.3";
        }

        throw new RuntimeException("Unhandled signatureAlgorithm: " + signatureAlgorithm);
    }

    private static byte[] P256_HEADER = Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgA=");

    private PublicKey generateP256PublicKeyFromPlain(byte[] plainSignature)
            throws InvalidKeySpecException, NoSuchAlgorithmException {

        byte[] encodedKey = new byte[P256_HEADER.length + plainSignature.length];

        System.arraycopy(P256_HEADER, 0, encodedKey, 0, P256_HEADER.length);
        System.arraycopy(plainSignature, 0, encodedKey, P256_HEADER.length, plainSignature.length);

        KeyFactory eckf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec ecpks = new X509EncodedKeySpec(encodedKey);

        return eckf.generatePublic(ecpks);
    }

    private byte[] convertPlainToDEREncodedSignature(byte[] concatenatedSignatureValue) throws IOException {
        byte[] r = new byte[33];
        byte[] s = new byte[33];
        System.arraycopy(concatenatedSignatureValue, 0, r, 1, 32);
        System.arraycopy(concatenatedSignatureValue, 32, s, 1, 32);

        BigInteger rBigInteger = new BigInteger(r);
        BigInteger sBigInteger = new BigInteger(s);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DERSequenceGenerator seqGen = new DERSequenceGenerator(bos);

        seqGen.addObject(new ASN1Integer(rBigInteger.toByteArray()));
        seqGen.addObject(new ASN1Integer(sBigInteger.toByteArray()));
        seqGen.close();
        bos.close();

        return bos.toByteArray();
    }
}
