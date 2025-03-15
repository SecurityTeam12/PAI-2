package secteam12.pai1.server;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ConnectSimulator {

    private static final String SERVER_ADDRESS = "127.0.0.1";
    private static final int SERVER_PORT = 3343;
    private static final int NUM_CONNECTIONS = 300;

    public static void main(String[] args) throws InterruptedException {
        ExecutorService executorService = Executors.newFixedThreadPool(300);

        for (int i = 0; i < NUM_CONNECTIONS; i++) {
            Thread.sleep(100);
            int connectionId = i + 1;
            executorService.submit(() -> {
                try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT)) {
                    System.out.println("Conexión establecida: " + connectionId);
                    Thread.sleep(100000000);
                } catch (IOException | InterruptedException e) {
                    System.err.println("Error en la conexión " + connectionId + ": " + e.getMessage());
                }
            });
        }
    }
}