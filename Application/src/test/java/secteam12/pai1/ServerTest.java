package secteam12.pai1;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.junit.jupiter.api.Test;
import secteam12.pai1.server.Server;
import secteam12.pai1.utils.MACUtil;

import java.io.*;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import secteam12.pai1.model.Message;
import secteam12.pai1.model.User;
import secteam12.pai1.repository.UserRepository;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ClassPathResource;


public class ServerTest extends Server{

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private Server server;

    @Mock
    private Resource trustStoreResource;

    @BeforeEach
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        // Ensure the trustStoreResource is properly initialized
        trustStoreResource = new ClassPathResource("saltserver_truststore.p12");
        server.trustStoreResource = trustStoreResource;

        // Ensure the server is running before tests
        Thread serverThread = new Thread(() -> {
            try {
                server.run((String[]) null);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        serverThread.start();
        // Add a delay to ensure the server is up before running tests
        try {
            Thread.sleep(2000); // Adjust the sleep time as needed
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testInvalidLoginProcess() throws Exception {
        Socket mockSocket = mock(Socket.class);
        BufferedReader mockInput = mock(BufferedReader.class);

        when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("Invalid User\n".getBytes()));
        when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());

        when(mockInput.readLine()).thenReturn("Invalid User");

        String username = "WrongUser";
        String password = "WrongPassword";

        List<User> users = simulateRepositoryResponse();
        when(userRepository.findAll()).thenReturn(users);

        User user = server.loginUser(username, password);
        assertNull(user);
        }


        @Test
        public void testRegisterDuplicateUser() throws Exception {
    
            Socket mockSocket = mock(Socket.class);
            BufferedReader mockInput = mock(BufferedReader.class);

            when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("User already exists.\n".getBytes()));
            when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());

            when(mockInput.readLine()).thenReturn("User already exists.");

            String username = "existingUser";
            String password = "Password123";

            User existingUser = new User();
            existingUser.setUsername(username);

            when(userRepository.findByUsername(username)).thenReturn(existingUser);

            int isRegistered = server.registerUser(username, password);
            assertEquals(-1,isRegistered);
        }

        @Test
        public void testSQLInjectionAttack() throws Exception {
            String maliciousUsername = "' OR '1'='1";
            String maliciousPassword = "' OR '1'='1";

            when(userRepository.findByUsername(maliciousUsername)).thenReturn(null);

            User user = server.loginUser(maliciousUsername, maliciousPassword);
            assertNull(user, "SQL Injection attack should not succeed");
        }

        @Test
        public void testBruteForceAttack() throws Exception {
            List<String> simulatedDicctionary = List.of("password", "123456", "qwerty", "letme in", "admin", "strongpassword", "password123", "12345678", "welcome", "monkey");
            String username = "testUser";
            String correctPassword = "Strong1@Password";

            List<User> users = simulateRepositoryResponse();
            when(userRepository.findAll()).thenReturn(users);

            for (String password : simulatedDicctionary) {

                User userTest = server.loginUser(username, password);
                assertNull(userTest, "Brute force attack attempt should not succeed");
            }
        }

        @Test
        public void testMessage() throws Exception {
            Socket mockSocket = mock(Socket.class);
            BufferedReader mockInput = mock(BufferedReader.class);
        
            when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("Message received\n".getBytes()));
            when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        
            when(mockInput.readLine()).thenReturn("Message received");

            String message = "Testing message";
            String nonce = MACUtil.generateNonce();
            String encodedKey = Base64.getEncoder().encodeToString(new byte[16]);
            String receivedMAC = MACUtil.generateMAC(message, nonce, new SecretKeySpec(new byte[16], "HmacSHA512"));
        
            when(mockInput.readLine()).thenReturn(message, nonce, encodedKey, receivedMAC);
        
            assertTrue(message.length() <= 255, "Message format should be valid");
        
            Message newMessage = new Message();
            newMessage.setMessageContent(message);
        
            assertEquals("Testing message", newMessage.getMessageContent());
        }
        
        @Test
        public void testInvalidMessage() throws Exception {
            Socket mockSocket = mock(Socket.class);
            BufferedReader mockInput = mock(BufferedReader.class);
        
            when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("Invalid message format\n".getBytes()));
            when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        
            when(mockInput.readLine()).thenReturn("Invalid message format");
        
            String message = "sourceAccount,destinationAccount";
            String nonce = MACUtil.generateNonce();
            String encodedKey = Base64.getEncoder().encodeToString(new byte[16]);
            String receivedMAC = MACUtil.generateMAC(message, nonce, new SecretKeySpec(new byte[16], "HmacSHA512"));
        
            when(mockInput.readLine()).thenReturn(message, nonce, encodedKey, receivedMAC);
        
            String[] parts = message.split(",");
            assertNotEquals(3, parts.length, "Message format should be invalid");
        }

        @Test
        public void testMessageMITMAttack() throws Exception {
            Socket mockSocket = mock(Socket.class);
            BufferedReader mockInput = mock(BufferedReader.class);
        
            when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("Message received\n".getBytes()));
            when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        
            when(mockInput.readLine()).thenReturn("Message received");
        
            String message = "sourceAccount,destinationAccount,100.0";
            String nonce = MACUtil.generateNonce();
            String encodedKey = Base64.getEncoder().encodeToString(new byte[16]);
            String receivedMAC = MACUtil.generateMAC(message, nonce, new SecretKeySpec(new byte[16], "HmacSHA512"));
        
            String modifiedMessage = "sourceAccount,destinationAccount,100000.0";
            String modifiedMAC = MACUtil.generateMAC(modifiedMessage, nonce, new SecretKeySpec(new byte[16], "HmacSHA512"));
        
            when(mockInput.readLine()).thenReturn(modifiedMessage, nonce, encodedKey, modifiedMAC);
        
            String[] parts = modifiedMessage.split(",");
            assertEquals(3, parts.length, "Message format should be valid");
        
            boolean isMACValid = MACUtil.verifyMAC(modifiedMessage, nonce, new SecretKeySpec(new byte[16], "HmacSHA512"), receivedMAC);
            assertFalse(isMACValid, "MAC should be invalid due to Man in the Middle attack");
        }

        private List<User> simulateRepositoryResponse(){

            String username = "testUser";
            String password = "Strong1@Password";
    
            // Generating a random salt
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            String saltBase64 = Base64.getEncoder().encodeToString(salt);

            String hash = getHashPassowrd(password, saltBase64);

            List<User> users = new ArrayList<>();
            User user = new User();
            user.setId(1); // Asegúrate de que el ID esté inicializado
            user.setUsername(username);
            user.setHash(hash);
            users.add(user);
    
            return users;
    
        }

        private String getHashPassowrd(String password, String salt){
            // Argon2 setup for password hashing
            Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
            int iterations = 10;
            int memory = 65536;
            int parallelism = 1;
            // Hash password
            return argon2.hash(iterations, memory, parallelism, (password + salt).toCharArray());
        }



    }
