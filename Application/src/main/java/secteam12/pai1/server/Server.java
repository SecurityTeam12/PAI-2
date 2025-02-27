package secteam12.pai1.server;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import secteam12.pai1.model.Transaction;
import secteam12.pai1.model.User;
import secteam12.pai1.repository.TransactionRepository;
import secteam12.pai1.repository.UserRepository;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import secteam12.pai1.utils.MACUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;

@Component
public class Server implements CommandLineRunner {

    @Autowired
    UserRepository userRepository;

    @Autowired
    TransactionRepository transactionRepository;

    @Value("classpath:userserver_keystore.p12")
    private Resource keyStoreResource;

    @Value("classpath:saltserver_truststore.p12")
    public Resource trustStoreResource;

    @Override
    public void run(String... args) throws Exception {
        SSLServerSocket serverSocket = null;
        try{
            char[] keystorePassword = "keystore".toCharArray();

            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (FileInputStream keyStoreFile = new FileInputStream(keyStoreResource.getFile())) {
                keyStore.load(keyStoreFile, "keystore".toCharArray());
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, keystorePassword);

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(kmf.getKeyManagers(), null, new SecureRandom());

            SSLServerSocketFactory ssf = sc.getServerSocketFactory();
            serverSocket = (SSLServerSocket) ssf.createServerSocket(3343);

            System.err.println("Server started and waiting for connections...");
            while (true) {
                try {
                    SSLSocket socket = (SSLSocket) serverSocket.accept();
                    System.err.println("Client connected.");

                    BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

                    String option = input.readLine();

                    if ("0".equals(option)) {
                        // Handle login

                    for(int i = 0; i < 3;i ++){

                        String nonce =  MACUtil.generateNonce();
                        output.println(nonce);

                        String encodedKey = input.readLine();
                        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
                        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA512");
                        String receivedMAC = input.readLine();

                        String userName = input.readLine();
                        if (userName == null) {
                            break;
                        }
                        String password = input.readLine();
                        if (password == null) {
                            break;
                        }


                        if(MACUtil.verifyMAC(userName+password, nonce, key, receivedMAC)){
                            User user = loginUser(userName, password);
                            if (user == null) {
                                output.println("Invalid login information");
                            } else {
                                output.println("Welcome, " + user.getUsername() + "!");
                                handleAuthenticatedUser(input, output, user);
                                break;
                            }
                        }
                    }

                } else if ("1".equals(option)) {
                    // Handle registration
                    String nonce =  MACUtil.generateNonce();
                    output.println(nonce);

                    String encodedKey = input.readLine();
                    byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
                    SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA512");
                    String receivedMAC = input.readLine();

                    String newUserName = input.readLine();
                    String newPassword = input.readLine();
                    if(newPassword.equals("null") || newUserName.equals("null")){
                        input.close();
                        output.close();
                        socket.close();
                        System.err.println("Client disconnected.");
                        continue;
                    }

                        if (MACUtil.verifyMAC(newUserName + newPassword, nonce, key, receivedMAC)) {
                            if (registerUser(newUserName, newPassword) == 1) {
                                output.println("Registration successful. You can now log in.");
                            } else if (registerUser(newUserName, newPassword) == -1) {
                                output.println("Registration failed. Username already exists.");
                            } else if (registerUser(newUserName, newPassword) == -2) {
                                output.println("Registration failed. Server not available. Contact the bank if the issue persists.");
                            }
                        }
                        
                    }

                    input.close();
                    output.close();
                    socket.close();
                    System.err.println("Client disconnected.");

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (serverSocket != null) {
                serverSocket.close();
            }
        }
        
    }

    public void handleAuthenticatedUser(BufferedReader input, PrintWriter output, User user) throws Exception {
        while (true) {
            String transactionsNumber = userRepository.findUserTransactionLenghtByUserId(user.getId()).toString();
            output.println(transactionsNumber);
            String option = input.readLine();
    
            if ("0".equals(option)) {
                String transaction = input.readLine();

                if (transaction.equals("null")) {
                    continue;
                }

                String nonce =  MACUtil.generateNonce();
                output.println(nonce);

                String encodedKey = input.readLine();
                byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
                SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA512");
                String receivedMAC = input.readLine();

                if (MACUtil.verifyMAC(transaction, nonce, key, receivedMAC)) {
                    String[] parts = transaction.split(",");

                    if (parts.length != 3) {
                        output.println("Invalid transaction format.");
                        continue;
                    }
                    

                    Transaction newTransaction = new Transaction();
                    newTransaction.setSourceAccount(parts[0]);
                    newTransaction.setDestinationAccount(parts[1]);
                    newTransaction.setAmount(Double.parseDouble(parts[2]));
                    newTransaction.setUser(user);

                    
                    transactionRepository.save(newTransaction);
                    output.println("Transaction received: " + transaction);
    
                } else {
                    output.println("Invalid MAC. Transaction rejected.");
                }
                
            } else if ("1".equals(option)) {
                break;
            } else {
                output.println("Invalid option selected.");
            }
        }
    }
	public User loginUser(String userName, String password) throws Exception {
        List<User> users = userRepository.findAll();

        // Argon2 setup for password hashing
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);


        for (User user : users) {
            if (user.getUsername().equals(userName) && argon2.verify(user.getHash(), (password + getSalt(user.getId())).toCharArray())) {
                return user;
            }
        }
        return null;
    }

    public int registerUser(String userName, String password) throws Exception {
        if (userRepository.findByUsername(userName) != null) {
            return -1; // Username already exists
        }

        // Argon2 setup for password hashing
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
        int iterations = 10;
        int memory = 65536;
        int parallelism = 1;

        // Generating a random salt
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        String saltBase64 = Base64.getEncoder().encodeToString(salt);

        // Hash password
        String hash = argon2.hash(iterations, memory, parallelism, (password + saltBase64).toCharArray());

        User newUser = new User();
        newUser.setUsername(userName);
        newUser.setHash(hash);
        // Ensure the ID is set before saving the user
        newUser = userRepository.save(newUser);
        if (newUser == null || newUser.getId() == null) {
            return -2; // Failed to save user
        }
        if(!saveSalt(newUser.getId(), saltBase64)) {
            userRepository.delete(newUser);
            return -2;
        }
        return 1;
    }
    public String getSalt(int id) throws Exception {
        String salt = "";
        if (trustStoreResource == null) {
            throw new IllegalStateException("TrustStore resource is not initialized.");
        }
        try {
            // Initializing an SSL/TLS connection in order to encrypt the communication
            char[] truststorePassword = "keystore".toCharArray();

            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream trustStoreIS = new FileInputStream(trustStoreResource.getFile())) {
                trustStore.load(trustStoreIS, truststorePassword);
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            SSLSocketFactory factory = sslContext.getSocketFactory();

            while (true) {
                SSLSocket clientSocket = (SSLSocket) factory.createSocket("localhost", 3344);

                BufferedReader input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter output = new PrintWriter(new OutputStreamWriter(clientSocket.getOutputStream()), true);

                output.println("1");
                output.println(id);
                String response = input.readLine();

                if(response.startsWith("Salt: ")) {
                    salt = response.substring(6);
                    break;
                } else if (response.equals("Salt not found.")) {
                    System.err.println("Salt of user " + userRepository.getByid(id).getUsername() + " not found.");
                    break;
                }

                input.close();
                output.close();
                clientSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return salt;
    }

    public boolean saveSalt(int userID, String salt) throws Exception {
        try {
            // Initializing an SSL/TLS connection in order to encrypt the communication
            char[] truststorePassword = "keystore".toCharArray();

            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream trustStoreIS = new FileInputStream(trustStoreResource.getFile())) {
                trustStore.load(trustStoreIS, truststorePassword);
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            SSLSocketFactory factory = sslContext.getSocketFactory();

            while (true) {
                try {
                    SSLSocket clientSocket = (SSLSocket) factory.createSocket("localhost", 3344);

                    BufferedReader input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                    PrintWriter output = new PrintWriter(new OutputStreamWriter(clientSocket.getOutputStream()), true);

                    output.println("2");
                    output.println("userID: " + userID);
                    output.println(salt);

                    // It could be simplified, but this way there is no need to save the salt in a variable to improve security.
                    // This part is needed to grant atomicity of the operation.
                    // The server will save a new user only if it is certain that the salt has been saved on the salt server.

                    if (input.readLine().equals("Salt " + salt + " saved for user " + userID)) {
                        input.close();
                        output.close();
                        clientSocket.close();
                        System.err.println("Salt saved.");
                        return true;
                    } else {
                        input.close();
                        output.close();
                        clientSocket.close();
                        System.err.println("Salt not saved.");
                        return false;
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    return false;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}