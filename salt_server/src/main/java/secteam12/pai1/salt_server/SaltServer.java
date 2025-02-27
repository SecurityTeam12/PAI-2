package secteam12.pai1.salt_server;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.SecureRandom;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import secteam12.pai1.salt_model.Salt;
import secteam12.pai1.salt_repository.SaltRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;

@Component
public class SaltServer implements CommandLineRunner {

    @Autowired
    private SaltRepository saltRepository;

    @Value("classpath:saltserver_keystore.p12")
    private Resource keyStoreResource;

    @Override
    public void run(String... args) throws Exception {

        SSLServerSocket serverSocket = null;

        try {

            // Initializing the server socket with SSL/TLS
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
            serverSocket = (SSLServerSocket) ssf.createServerSocket(3344);

            System.err.println("Salt Server started and waiting for connections...");

            while (true) {
                try {
                    SSLSocket socket = (SSLSocket) serverSocket.accept();
                    // Verify that the connecting client has a specific IP address and port to make sure that it is the users server.
                    if (!socket.getInetAddress().getHostAddress().equals("127.0.0.1")/*|| socket.getPort() != 12345*/) {
                        System.err.println("Connection from unauthorized client. IP: " + socket.getInetAddress().getHostAddress() + ", Port: " + socket.getPort());
                        socket.close();
                        continue;
                    }

                    System.err.println("Client connected.");

                    BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

                    // Operation 1 = Get salt from database
                    // Operation 2 = Save new salt to database
                    String operation = input.readLine();

                    if (operation.equals("1")) {
                        int userId = Integer.parseInt(input.readLine());
                        Salt salt = saltRepository.findByid(userId);
                        if (salt != null) {
                            output.println("Salt: " + saltRepository.findByid(userId).getSalt());
                        } else {
                            output.println("Salt not found.");
                        }
                    } else if (operation.equals("2")) {
                        String newSalt = input.readLine();
                        if (newSalt.startsWith("userID: ")) {
                            int userId = Integer.parseInt(newSalt.substring(8));
                            newSalt = input.readLine();
                            Salt salt = new Salt();
                            salt.setId(userId);
                            salt.setSalt(newSalt);
                            saltRepository.save(salt);
                            output.println("Salt " + salt.getSalt() + " saved for user " + salt.getId());
                            System.err.println("New salt saved for user " + userId);
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
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (serverSocket != null) {
                serverSocket.close();
            }
        }
    }
}
