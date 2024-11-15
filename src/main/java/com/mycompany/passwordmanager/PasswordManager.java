/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.passwordmanager;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
/**
 *
 * @author Domantas & Nojus &
 */
public class PasswordManager {
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final int SALT_LENGTH = 16;

    // map to store acc and encrypted passwords (not including salt and masterHash)
    private Map<String, String> passwordStore = new HashMap<>();
    private SecretKey encryptionKey;

    private String masterHash;
    private byte[] salt;

    // constructer for salt, master hash, and encryption key
    public PasswordManager(String masterPassword) throws Exception {
        salt = generateSalt();
        masterHash = hashPassword(masterPassword, salt);
        encryptionKey = generateEncryptionKey(masterPassword);
    }

    // hashing for the master password
    private String hashPassword(String password, byte[] salt) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        digest.update(salt);
        byte[] hashedBytes = digest.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hashedBytes);
    }

    // makes a random salt
    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    // verifies the master password by hashing and comparing it with the stored hash
    public boolean verifyMasterPassword(String password) throws Exception {
        String hashedPassword = hashPassword(password, salt);
        return masterHash.equals(hashedPassword);
    }

    // makes an AES key from the master password
    private SecretKey generateEncryptionKey(String password) throws Exception {
        MessageDigest sha = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] key = sha.digest(password.getBytes());
        return new SecretKeySpec(key, 0, 16, ENCRYPTION_ALGORITHM);
    }

    // encyrpts a given password
    public String encryptPassword(String password) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // decyrpts an encrypted password
    public String decryptPassword(String encryptedPassword) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(decryptedBytes);
    }

    // sotres an encrypted password for account
    public void storePassword(String account, String password) throws Exception {
        String encryptedPassword = encryptPassword(password);
        passwordStore.put(account, encryptedPassword);
    }

    // retrieves and decrypts a password for account
    public String retrievePassword(String account) throws Exception {
        String encryptedPassword = passwordStore.get(account);
        if (encryptedPassword != null) {
            return decryptPassword(encryptedPassword);
        }
        return null;
    }

    // removes a stored password for an account
    public void removePassword(String account) {
        passwordStore.remove(account);
    }

    // gets all accounts without salt and master hash
    public Map<String, String> getAllAccounts() {
        return new HashMap<>(passwordStore);  // System fields are excluded since they're not in passwordStore
    }

    public static void main(String[] args) throws Exception {
        LoginGUI loginGUI = new LoginGUI();
        loginGUI.setVisible(true);

    }
}