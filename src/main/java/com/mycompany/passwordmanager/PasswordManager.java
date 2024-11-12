/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.passwordmanager;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
/**
 *
 * @author kdoma
 */
public class PasswordManager {
        private static final String HASH_ALGORITHM = "SHA-256";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final int SALT_LENGTH = 16;

    // Map to store user accounts and encrypted passwords
    private Map<String, String> passwordStore = new HashMap<>();
    private SecretKey encryptionKey;

    public PasswordManager(String masterPassword) throws Exception {
        byte[] salt = generateSalt();
        String hashedPassword = hashPassword(masterPassword, salt);
        encryptionKey = generateEncryptionKey(masterPassword);
        passwordStore.put("masterHash", hashedPassword);
        passwordStore.put("salt", Base64.getEncoder().encodeToString(salt));
    }

    // Hashing function for the master password
    private String hashPassword(String password, byte[] salt) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        digest.update(salt);
        byte[] hashedBytes = digest.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hashedBytes);
    }

    // Generates a random salt
    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    // Verifies the master password
    public boolean verifyMasterPassword(String password) throws Exception {
        String storedHash = passwordStore.get("masterHash");
        byte[] salt = Base64.getDecoder().decode(passwordStore.get("salt"));
        String hashedPassword = hashPassword(password, salt);
        return storedHash.equals(hashedPassword);
    }

    // Generate an AES key from the master password
    private SecretKey generateEncryptionKey(String password) throws Exception {
        MessageDigest sha = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] key = sha.digest(password.getBytes());
        return new SecretKeySpec(key, 0, 16, ENCRYPTION_ALGORITHM);
    }

    // Encrypts the password
    public String encryptPassword(String password) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypts the password
    public String decryptPassword(String encryptedPassword) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(decryptedBytes);
    }

    // Stores a password for a specific account
    public void storePassword(String account, String password) throws Exception {
        String encryptedPassword = encryptPassword(password);
        passwordStore.put(account, encryptedPassword);
    }

    // Retrieves the password for a specific account
    public String retrievePassword(String account) throws Exception {
        String encryptedPassword = passwordStore.get(account);
        if (encryptedPassword != null) {
            return decryptPassword(encryptedPassword);
        }
        return null;
    }
    
    public void removePassword(String account) {
    passwordStore.remove(account);
}
    
 public Map<String, String> getAllAccounts() {
    return new HashMap<>(passwordStore);
}   
    public static void main (String[] args) throws Exception{
        LoginGUI loginGUI = new LoginGUI();
        loginGUI.setVisible(true);
        
        PasswordManager manager = new PasswordManager("MyMasterPassword");
        
        // Verify master password
        if (manager.verifyMasterPassword("MyMasterPassword")) {
            System.out.println("Master password verified!");

            // Store and retrieve a password
            manager.storePassword("example.com", "myPassword123");
            String retrievedPassword = manager.retrievePassword("example.com");
            System.out.println("Retrieved password: " + retrievedPassword);
        } else {
            System.out.println("Incorrect master password!");
        }
        
    }
    
}
