package at.ijt.tse_sig_verification;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

public class QrCodeSignatureVerifier {
    public boolean verify(String qrCodeString) {
        try {
            byte[] rawdata = createRawDataFromQrCode(qrCodeString);
            byte[] signature = createDerSignatureFromQrCode(qrCodeString);
            PublicKey publicKey = createPublicKeyFromQrCode(qrCodeString);
            Signature verifier = createVeriferFromQrCode(qrCodeString);

            verifier.initVerify(publicKey);
            verifier.update(rawdata);

            return verifier.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Signature createVeriferFromQrCode(String qrCodeString) throws NoSuchAlgorithmException {
        String[] parts = qrCodeString.split(";");
        String signatureAlgorithm = parts[8];

        return Signature.getInstance(mapSignatureAlgorithm(signatureAlgorithm));
    }

    private PublicKey createPublicKeyFromQrCode(String qrCodeString)
            throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidParameterSpecException {
        String[] parts = qrCodeString.split(";");
        byte[] plainPublicKey = Utils.decodeBase64(parts[11]);
        String signatureAlgorithm = parts[8];
        String curve = mapSignatureAlgorithmToCurve(signatureAlgorithm);

        return ucPublicKeyToPublicKey(curve, plainPublicKey);
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
        long signatureCounter = Long.parseLong(parts[5]);
        String dateTimeString = parts[7];
        String signatureAlgorithm = mapSignatureAlgorithmToOid(parts[8]);
        String logTimeFormat = parts[9];
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

        if ("unixTime".equals(logTimeFormat)) {
            dos.writeObject(new ASN1Integer(Utils.convertISO8601DateStringToUnixTime(dateTimeString)));
        } else if ("utcTime".equals(logTimeFormat)) {
            dos.writeObject(new ASN1UTCTime(Utils.convertISO8601DateStringToDate(dateTimeString)));
        } else if ("generalizedTime".equals(logTimeFormat)) {
            dos.writeObject(new ASN1GeneralizedTime(Utils.convertISO8601DateStringToDate(dateTimeString)));
        } else {
            throw new RuntimeException("Unhandled logTimeFormat: " + logTimeFormat);
        }

        dos.close();

        return baos.toByteArray();
    }

    private PublicKey ucPublicKeyToPublicKey(String curveName, byte[] rawPublicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(curveName);
        ECCurve curve = ecNamedCurveParameterSpec.getCurve();
        EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, ecNamedCurveParameterSpec.getSeed());
        ECPoint ecPoint = ECPointUtil.decodePoint(ellipticCurve, rawPublicKey);
        ECParameterSpec ecParameterSpec = EC5Util.convertSpec(ellipticCurve, ecNamedCurveParameterSpec);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);

        return KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
    }

    private byte[] convertPlainToDEREncodedSignature(byte[] concatenatedSignatureValue) throws IOException {
        int length = concatenatedSignatureValue.length / 2;
        byte[] r = new byte[length + 1];
        byte[] s = new byte[length + 1];

        System.arraycopy(concatenatedSignatureValue, 0, r, 1, length);
        System.arraycopy(concatenatedSignatureValue, length, s, 1, length);

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

    private String mapSignatureAlgorithm(String signatureAlgorithm) {
        if ("ecdsa-plain-SHA256".equals(signatureAlgorithm)) {
            return "SHA256withECDSA";
        }

        if ("ecdsa-plain-SHA384".equals(signatureAlgorithm)) {
            return "SHA384withECDSA";
        }

        throw new RuntimeException("Unhandled signatureAlgorithm: " + signatureAlgorithm);
    }

    private String mapSignatureAlgorithmToOid(String signatureAlgorithm) {
        if ("ecdsa-plain-SHA256".equals(signatureAlgorithm)) {
            return "0.4.0.127.0.7.1.1.4.1.3";
        }

        if ("ecdsa-plain-SHA384".equals(signatureAlgorithm)) {
            return "0.4.0.127.0.7.1.1.4.1.4";
        }

        throw new RuntimeException("Unhandled signatureAlgorithm: " + signatureAlgorithm);
    }

    private String mapSignatureAlgorithmToCurve(String signatureAlgorithm) {
        if ("ecdsa-plain-SHA256".equals(signatureAlgorithm)) {
            return "secp256r1";
        }

        if ("ecdsa-plain-SHA384".equals(signatureAlgorithm)) {
            return "brainpoolP384r1";
        }

        throw new RuntimeException("Unhandled signatureAlgorithm: " + signatureAlgorithm);
    }
}
