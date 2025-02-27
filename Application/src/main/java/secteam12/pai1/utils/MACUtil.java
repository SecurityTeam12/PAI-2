package secteam12.pai1.utils;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;

public class MACUtil {
    private static final String HMAC_SHA512 = "HmacSHA512";

    public static String generateNonce() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[16];
        secureRandom.nextBytes(nonce);
        return Base64.getEncoder().encodeToString(nonce);
    }

    public static String generateMAC(String message, String nonce,SecretKey key) throws Exception {
        String data = message + nonce;
        Mac mac = Mac.getInstance(HMAC_SHA512);
        mac.init(key);
        mac.update(data.getBytes());
        byte[] macBytes = mac.doFinal();
        return Base64.getEncoder().encodeToString(macBytes);
    }

    public static boolean verifyMAC(String message, String nonce, SecretKey key,String receivedMAC) throws Exception {
        String calculatedMAC = generateMAC(message, nonce,key);
        return calculatedMAC.equals(receivedMAC);
    }
}
