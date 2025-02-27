package secteam12.pai1.utils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;

public class PwnedPasswordChecker {

    private static final String API_ROOT = "https://api.pwnedpasswords.com/range/";

    public static boolean isPasswordPwned(String password) throws Exception {

        String hashedPassword = hashPassword(password);
        String prefix = hashedPassword.substring(0, 5);
        String suffix = hashedPassword.substring(5);
        String url = API_ROOT + prefix;

        String response = sendGetRequest(url);

        return response.contains(suffix.toUpperCase());
    }

    private static String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hashedBytes = md.digest(password.getBytes("UTF-8"));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hashedBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static String sendGetRequest(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine).append("\n");
        }
        in.close();

        return response.toString();
    }
}

