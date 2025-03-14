package secteam12.pai1.server;
import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.util.concurrent.CountDownLatch;

public class ConnectSimulator {
    public static void main(String[] args) throws Exception {
        final int numberOfConnections = 300;
        char[] truststorePassword = "keystore".toCharArray();

        KeyStore trustStore = KeyStore.getInstance("JKS");
        String trustStorePath = "Application" + File.separator + "src" + File.separator + "main" + File.separator + "resources" + File.separator + "client_truststore.p12";
        try (InputStream trustStoreIS = new FileInputStream(trustStorePath)) {
            trustStore.load(trustStoreIS, truststorePassword);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);

        SSLSocketFactory factory = sslContext.getSocketFactory();

        CountDownLatch latch = new CountDownLatch(1);

        for (int i = 0; i < numberOfConnections; i++) {
            final int connectionNumber = i;
            new Thread(() -> {
                SSLSocket socket = null;
                try {
                    latch.await(); // Espera hasta que el latch se cuente hacia abajo a 0
                    socket = (SSLSocket) factory.createSocket("localhost", 3343);
                    socket.startHandshake();
                    System.out.println("Conexión SSL establecida: " + connectionNumber);

                    BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

                    String response;
                    while ((response = reader.readLine()) != null) {
                        System.out.println("Respuesta del servidor: " + response);
                    }
                } catch (IOException | InterruptedException e) {
                    e.printStackTrace();
                } finally {
                    if (socket != null) {
                        try {
                            socket.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }).start();
        }

        // Inicia todas las conexiones simultáneamente
        latch.countDown();
    }
}