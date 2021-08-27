package at.ijt.tse_sig_verification;

public class App {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Argument <qr-code> missing");
            System.exit(1);
        }

        System.out.println(new QrCodeSignatureVerifier().verify(args[0]));
    }

}
