package secteam12.pai1;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

import java.security.SecureRandom;
import java.util.Base64;

public class Argon2Example {

    public static void main(String[] args) {
        // Create instance
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

        // Read password from user
        char[] password1 = "password1".toCharArray();
        char[] password2 = "password2".toCharArray();
        int iterations = 10;
        int memory = 65536;
        int parallelism = 1;

        // Generate two random salts
        byte[] salt1 = new byte[32];
        byte[] salt2 = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt1);
        random.nextBytes(salt2);
        String saltBase64_1 = Base64.getEncoder().encodeToString(salt1);
        String saltBase64_2 = Base64.getEncoder().encodeToString(salt2);

        try {
            // Hash password with first salt
            String hash1 = argon2.hash(iterations, memory, parallelism, (new String(password1) + saltBase64_1).toCharArray());

            // Hash password with second salt
            String hash2 = argon2.hash(iterations, memory, parallelism, (new String(password2) + saltBase64_2).toCharArray());

            // Print the hashes and salts
            System.out.println("Hash 1: " + hash1);
            System.out.println("Salt 1 (Base64): " + saltBase64_1);
            System.out.println("Hash 2: " + hash2);
            System.out.println("Salt 2 (Base64): " + saltBase64_2);
        } finally {
            // Wipe confidential data
            argon2.wipeArray(password1);
            argon2.wipeArray(password2);
        }
    }
}
