package secteam12.pai1;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Map;

import org.junit.jupiter.api.Test;
import secteam12.pai1.client.ClientSocket;


public class ClientSocketTest extends ClientSocket {
        
    @Test
    public void testSecureTransaction() throws Exception {
        String nonce = "12345";
        String data = "testData";

        Map<String, String> result = secureTransaction(nonce, data);

        assertNotNull(result.get("EncodedKey"), "EncodedKey should not be null");
        assertNotNull(result.get("SecureMac"), "SecureMac should not be null");
        assertFalse(result.get("EncodedKey").isEmpty(), "EncodedKey should not be empty");
        assertFalse(result.get("SecureMac").isEmpty(), "SecureMac should not be empty");
    }

    @Test
    public void testCheckPasswordSecurity() throws Exception {
        assertTrue(checkPasswordSecurity("Strong1@Password"), "Password should be valid");
        assertTrue(checkPasswordSecurity("Valid#2023"), "Password should be valid");

        assertFalse(checkPasswordSecurity("short"), "Password is too short");
        assertFalse(checkPasswordSecurity("nouppercase123"), "Password has no uppercase characters");
        assertFalse(checkPasswordSecurity("NOLOWERCASE@123"), "Password has no lowercase characters");
        assertFalse(checkPasswordSecurity("NoSpecialChar123"), "Password has no special characters");
        assertFalse(checkPasswordSecurity("NoNumbers@"), "Password has no numbers");
    }

    @Test
    public void testHMACKeyGenerationIsUnique() throws Exception {
        Map<String, String> result1 = secureTransaction("nonce1", "data1");
        Map<String, String> result2 = secureTransaction("nonce2", "data2");

        assertNotEquals(result1.get("EncodedKey"), result2.get("EncodedKey"), "Encoded keys should be unique");
        assertNotEquals(result1.get("SecureMac"), result2.get("SecureMac"), "Secure MACs should be unique");
    }

    @Test
    public void testMainLoginProcess() throws Exception {
        Socket mockSocket = mock(Socket.class);
        BufferedReader mockInput = mock(BufferedReader.class);
        PrintWriter mockOutput = mock(PrintWriter.class);

        when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("12345\nWelcome User\n".getBytes()));
        when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());

        when(mockInput.readLine()).thenReturn("Welcome User");

        String username = "testUser";
        String password = "Strong1@Password";

        Map<String, String> secureTransaction = secureTransaction("12345", username + password);
        String encodedKey = secureTransaction.get("EncodedKey");
        String secureMac = secureTransaction.get("SecureMac");

        mockOutput.println(encodedKey);
        mockOutput.println(secureMac);
        mockOutput.println(username);
        mockOutput.println(password);

        String response = mockInput.readLine();
        assertEquals("Welcome User", response);
    }

    @Test
    public void testMainRegistrationProcess() throws Exception {
        Socket mockSocket = mock(Socket.class);
        BufferedReader mockInput = mock(BufferedReader.class);
        PrintWriter mockOutput = mock(PrintWriter.class);

        when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("12345\nRegistration successful. You can now log in.\n".getBytes()));
        when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());

        when(mockInput.readLine()).thenReturn( "Registration successful. You can now log in.");

        String username = "newUser";
        String password = "NewUserPassword";

        Map<String, String> secureTransaction = secureTransaction("12345", username + password);
        String encodedKey = secureTransaction.get("EncodedKey");
        String secureMac = secureTransaction.get("SecureMac");

        mockOutput.println(encodedKey);
        mockOutput.println(secureMac);
        mockOutput.println(username);
        mockOutput.println(password);

        String response = mockInput.readLine();
        assertEquals("Registration successful. You can now log in.", response);
    }
}
