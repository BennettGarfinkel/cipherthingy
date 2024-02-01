import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.Scanner;

public class cipher {
    static char ch;
    static int valueAt = 0;
    static String finalMessage = "";
    static String encryptedKey = "";

    public static String encrypt256(String strToEncrypt, String key, String salt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(key.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e);
        }
        return null;
    }

    public static String decrypt256(String strToDecrypt, String key, String salt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(key.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e);
        }
        return null;
    }

    static String encryptText(String message, String salt, String key) {
        encryptedKey = encryptKey(key);
        finalMessage = "";
        //apply key
        assert message != null;
        for (int i = message.length(); i >= 1; --i) {            
                ch = message.charAt(valueAt);
                if (i % 2 == 1) {
                    ch =(char) (ch + i);
                }else {

                   ch =(char) (ch - i);
                }
                valueAt += 1;
                finalMessage += ch;
            
        }
        valueAt = 0;
        finalMessage = encrypt256(finalMessage, key, salt);

        return finalMessage;
    }
    static String decryptText(String message, String salt,String key) {
        message = decrypt256(message, key, salt);
        encryptedKey = encryptKey(key);
        finalMessage = "";
        //unapply key
        assert message != null;
        for (int i = message.length(); i >= 1; --i) {
                ch = message.charAt(valueAt);
                if (i % 2 == 1) {
                    ch =(char) (ch - i);
                } else {
                   ch =(char) (ch + i);
                }
                valueAt += 1;
                finalMessage += ch;
            
        }
        valueAt = 0;
        return finalMessage;
    }

    static String encryptKey(String message) {
        for (int i = 1; i <= Objects.requireNonNull(message).length(); ++i) {
            {
                ch = message.charAt(valueAt);
                if (i % 2 == 1 || i == 1) {
                    ch =(char) (ch + i);
                } else {
                    ch =(char) (ch - i);
                }
                valueAt += 1;
                finalMessage += ch;
            }
        }
        
        valueAt = 0;
        return finalMessage;
}


    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String slt = "";
        String key = "";
        String answer;
        System.out.println("Please enter message");
        String mssg = scanner.nextLine();
        System.out.println("Encode or Decode?");
        String eord = scanner.nextLine();
        System.out.println("Please enter salt");
        slt = scanner.nextLine();
        System.out.println("Please enter key");
        key = scanner.nextLine();
        answer = "";
        if ((String.valueOf(eord.charAt(0))).equals("e"))
        {
            answer = encryptText(mssg, slt, key);
        }
        if ((String.valueOf(eord.charAt(0))).equals("d"))
        {
            answer = decryptText(mssg, slt, key);
        }
        System.out.println(answer);
        scanner.close();
    }

}
