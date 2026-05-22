package com.example.vuln;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public class CryptoService {
    private static final byte[] KEY = "1234567890abcdef".getBytes(); // hardcoded symmetric key

    public String sha1(String value) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1"); // weak hash
        byte[] digest = md.digest(value.getBytes("UTF-8"));
        return javax.xml.bind.DatatypeConverter.printHexBinary(digest);
    }

    public byte[] encrypt(byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // insecure ECB mode
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
        return cipher.doFinal(plaintext);
    }
}
