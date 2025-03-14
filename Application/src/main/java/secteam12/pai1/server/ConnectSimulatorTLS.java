package secteam12.pai1.server;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ConnectSimulatorTLS {
    private static final int NUMBER_OF_CONNECTIONS = 300;
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 3343;
    private static final String KEYSTORE_PASSWORD = "keystore";
    private static final String KEYSTORE_PATH = "Application" + File.separator + "src" + File.separator 
            + "main" + File.separator + "resources" + File.separator + "client_keystore.jks";
    private static final String TRUSTSTORE_PASSWORD = "keystore";
    private static final String TRUSTSTORE_PATH = "Application" + File.separator + "src" + File.separator 
            + "main" + File.separator + "resources" + File.separator + "client_truststore.jks";

    public static void main(String[] args) throws Exception {
        // Configurar el KeyStore del Cliente
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream keyStoreIS = new FileInputStream(KEYSTORE_PATH)) {
            keyStore.load(keyStoreIS, KEYSTORE_PASSWORD.toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

        // Configurar el TrustStore del Cliente
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream trustStoreIS = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(trustStoreIS, TRUSTSTORE_PASSWORD.toCharArray());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLSocketFactory factory = sslContext.getSocketFactory();

        ExecutorService executorService = Executors.newFixedThreadPool(NUMBER_OF_CONNECTIONS);
        CountDownLatch latch = new CountDownLatch(1);

        for (int i = 0; i < NUMBER_OF_CONNECTIONS; i++) {
            final int connectionId = i + 1;
            executorService.submit(() -> {
                SSLSocket socket = null;
                try {
                    latch.await();
                    socket = (SSLSocket) factory.createSocket(SERVER_HOST, SERVER_PORT);
                    socket.startHandshake();
                    System.out.println("Conexión TLS establecida");
                } catch (Exception e) {
                    System.err.println("Error en la conexión " + connectionId + ": " + e.getMessage());
                } finally {
                    if (socket != null) {
                        try {
                            socket.close();
                        } catch (IOException e) {
                            System.err.println("Error al cerrar el socket " + connectionId + ": " + e.getMessage());
                        }
                    }
                }
            });
        }

        latch.countDown();
        executorService.shutdown();
    }
}
