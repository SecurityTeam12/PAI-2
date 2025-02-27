package secteam12.pai1.client;

import secteam12.pai1.utils.MACUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.swing.*;
import java.io.*;
import java.security.KeyStore;
import java.util.Base64;
import java.util.Map;
import java.net.Socket;
import java.util.Base64;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.JOptionPane;


import secteam12.pai1.utils.MACUtil;

public class ClientSocket {
    private static final String HMAC_SHA512 = "HmacSHA512";

    public static void main(String[] args) throws Exception{

        // Initializing an SSL/TLS connection in order to encrypt the communication
        char[] truststorePassword = "keystore".toCharArray();

        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream trustStoreIS = new FileInputStream("Application/src/main/resources/client_truststore.p12")) {
            trustStore.load(trustStoreIS, truststorePassword);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);

        SSLSocketFactory factory = sslContext.getSocketFactory();

        try {
            // connect to server
            while(true){

                // create SSLSocket and initializing handshake
                SSLSocket socket = (SSLSocket) factory.createSocket("localhost", 3343);
                socket.startHandshake();

                // create PrintWriter for sending data to server
                PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

                // create BufferedReader for reading server response
                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                int option = JOptionPane.showOptionDialog(null, "WELCOME TO INTEGRIDOS", "Select an option", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, new String[] { "Login", "Register" },null);

                // send selected option to server
                output.println(option);

                if (option == 0) {
                    for (int i = 0; i < 3; i++) {
                        String nonce  =  input.readLine();
                        String userName = JOptionPane.showInputDialog("Enter username:");
                        if(userName == null){
                            output.println(userName);
                            break;
                        }
                        String password = JOptionPane.showInputDialog("Enter password:");
                        if(password == null){
                            output.println(password);
                            break;
                        }

                        Map<String,String> secureTransaction = secureTransaction(nonce, userName + password);
                        String encodedKey = secureTransaction.get("EncodedKey");
                        String secureMac = secureTransaction.get("SecureMac");

                        output.println(encodedKey);
                        output.println(secureMac);
                        output.println(userName);
                        output.println(password);

                        // read response from server
                        String response = input.readLine();
                        if (response.startsWith("Welcome")) {
                            handleAuthenticatedUser(input, output,response);
                            break;
                        }else{
                            Thread.sleep(3000);
                            JOptionPane.showMessageDialog(null, response);
                            if(i == 2){
                                JOptionPane.showMessageDialog(null, "Too many login attempts. Exiting...");
                            }
                        }
                    }

                } else if (option == 1) {
                    // Handle registration
                    String newUserName = null;
                    String newPassword = null;
                    while(true){
                        newUserName = JOptionPane.showInputDialog("Enter new username:");
                        if(newUserName == null){
                            break;
                        }
                        newPassword = JOptionPane.showInputDialog("Enter new password:");
                        if(newPassword == null){
                            break;
                        }
                        if(!checkPasswordSecurity(newPassword)){
                            JOptionPane.showMessageDialog(null, "Password does not meet security requirements.");
                        }else{
                            break;
                        }
                    }

                    String nonce  =  input.readLine();
                    Map<String,String> secureTransaction = secureTransaction(nonce, newUserName + newPassword);
                    String encodedKey = secureTransaction.get("EncodedKey");
                    String secureMac = secureTransaction.get("SecureMac");

                    output.println(encodedKey);
                    output.println(secureMac);
                    output.println(newUserName);
                    output.println(newPassword);

                    if(newUserName == null || newPassword == null){
                        continue;
                    }
                    // read response from server
                    String response = input.readLine();
                    JOptionPane.showMessageDialog(null, response);

                } else {
                    break;
                }

                // clean up streams and Socket
                output.close();
                input.close();
                socket.close();
            }
            

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void handleAuthenticatedUser(BufferedReader input, PrintWriter output,String welcome) throws Exception {
        while (true) {
            // read and display authenticated user menu options from server

            String transactionNumber = input.readLine();
            String transactionNumberMessage = "You sent " + transactionNumber + " transactions.";

            String menu = welcome + "\n" + transactionNumberMessage + "\n" +  "Select an option";
            int option = JOptionPane.showOptionDialog(null, menu, "Select an option", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, new String[] { "Perform a Transaction", "Logout" },null);

            // send selected option to server
            output.println(option);

            if (option == 0) {
                // Handle transaction
                String transaction = JOptionPane.showInputDialog("Enter transaction in format 'Cuenta origen, Cuenta destino, Cantidad transferida':");
                output.println(transaction);
                if (transaction == null) {
                    continue;
                }
                String nonce  =  input.readLine();

                // read response from server
                Map<String,String> secureTransaction = secureTransaction(nonce, transaction);
                String encodedKey = secureTransaction.get("EncodedKey");
                String secureMac = secureTransaction.get("SecureMac");

                output.println(encodedKey);
                output.println(secureMac);

                String response = input.readLine();
                JOptionPane.showMessageDialog(null, response);

            } else if (option == 1) {
                // Handle logout
                JOptionPane.showMessageDialog(null, "Logged out successfully.");
                break;

            } else {
                break;
            }
        }
    }

    protected static Map<String,String> secureTransaction(String nonce, String data) throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance(HMAC_SHA512);
        SecretKey key = keyGenerator.generateKey();
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        String secureMac = MACUtil.generateMAC(data, nonce,key);

        return Map.of("EncodedKey", encodedKey, "SecureMac", secureMac);
    }

    protected static Boolean checkPasswordSecurity(String password) throws Exception {
        Boolean hasUppercase = !password.equals(password.toLowerCase());
        Boolean hasLowercase = !password.equals(password.toUpperCase());
        Boolean hasNumber = password.matches(".*\\d.*");
        Boolean hasSpecialChar = !password.matches("[A-Za-z0-9 ]*");
        Boolean hasCorrectLength = password.length() >= 8;


        if (hasUppercase && hasLowercase && hasNumber && hasSpecialChar && hasCorrectLength) {
            return true;
        }
        return false;


    }

}