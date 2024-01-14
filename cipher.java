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

    static String rBackwards(String message, String salt, String code, String key) {
        code = code.toLowerCase();

        boolean e = ((String.valueOf(code.charAt(0)))).equals("e");

        boolean d = ((String.valueOf(code.charAt(0)))).equals("d");
        if (d) {
            assert message != null;

            message = decrypt256(message, key, salt);

        }
        finalMessage = "";
        assert message != null;
        for (int i = message.length(); i >= 1; --i) {
            {
                ch = message.charAt(valueAt);
                if (i % 2 == 1) {
                    /*if ((ch + i) < 255) {*/ch =(char) (ch + i);//}
                    //else if ((ch+i) > 255) {int extra = (ch+i) - 255; ch = (char)(32+extra);}
                } else {

                   /* if ((ch - i) > 32) {*/ch =(char) (ch - i);//}
                    //else if ((ch-i) < 32) {int extra = 32 - (ch-i); ch = (char)(255-extra);}
                }
                valueAt += 1;
                finalMessage += ch;
            }
        }
        valueAt = 0;

        if (e) {
            assert finalMessage != null;
            finalMessage = encrypt256(finalMessage, key, salt);

        }
        return finalMessage;
    }

    static String backwards(String message, String salt, String code, String key) {
        code = code.toLowerCase();

        boolean e = ((String.valueOf(code.charAt(0)))).equals("e");

        boolean d = ((String.valueOf(code.charAt(0)))).equals("d");
        if (d) {
            assert message != null;

            message = decrypt256(message, key, salt);

        }
        finalMessage = "";
        assert message != null;
        for (int i = message.length(); i >= 1; --i) {
            {
                ch = message.charAt(valueAt);
                if (i % 2 == 1) {
                    /*if ((ch - i) > 32) {*/ch =(char) (ch - i);//}
                    //else if ((ch-i) < 32) {int extra = 32 - (ch-i); ch = (char)(255-extra);}
                } else {
                   /* if ((ch + i) < 255) {*/ch =(char) (ch + i);//}
                    //else if ((ch+i) > 255) {int extra = (ch+i) - 255; ch = (char)(32+extra);}
                }
                valueAt += 1;
                finalMessage += ch;
            }
        }
        valueAt = 0;

        if (e) {
            assert finalMessage != null;
            finalMessage = encrypt256(finalMessage, key, salt);

        }
        return finalMessage;
    }

    static String forwards(String message, String salt, String code, String key) {
        code = code.toLowerCase();

        boolean e = ((String.valueOf(code.charAt(0)))).equals("e");

        boolean d = ((String.valueOf(code.charAt(0)))).equals("d");
        if (d) {
            assert message != null;

            message = decrypt256(message, key, salt);

        }
        finalMessage = "";
        for (int i = 1; i <= Objects.requireNonNull(message).length(); ++i) {
            {
                ch = message.charAt(valueAt);
                if (i % 2 == 1 || i == 1) {
                    /*if ((ch + i) < 255) {*/ch =(char) (ch + i);//}
                    //else if ((ch+i) > 255) {int extra = (ch+i) - 255; ch = (char)(32+extra);}
                } else {
                    /*if ((ch - i) > 32) {*/ch =(char) (ch - i);//}
                    //else if ((ch-i) < 32) {int extra = 32 - (ch-i); ch = (char)(255-extra);}
                }
                valueAt += 1;
                finalMessage += ch;
            }
        }
        valueAt = 0;

        if (e) {
            assert finalMessage != null;
            finalMessage = encrypt256(finalMessage, key, salt);

        }
        return finalMessage;
    }

    static String rForwards(String message, String salt, String code, String key) {
        code = code.toLowerCase();

        boolean e = ((String.valueOf(code.charAt(0)))).equals("e");
        boolean d = ((String.valueOf(code.charAt(0)))).equals("d");
        if (d) {
            assert message != null;
            message = decrypt256(message, key, salt);

        }
        finalMessage = "";
        for (int i = 1; i <= Objects.requireNonNull(message).length(); ++i) {
            {
                ch = message.charAt(valueAt);
                if (i % 2 ==  1 || i ==  1) {
                    /*if ((ch - i) > 32) {*/ch =(char) (ch - i);//}
                    //else if ((ch-i) < 32) {int extra = 32 - (ch-i); ch = (char)(255-extra);}
                } else {
                    /*if ((ch + i) < 255) {*/ch =(char) (ch + i);//}
                    //else if ((ch+i) > 255) {int extra = (ch+i) - 255; ch = (char)(32+extra);}
                }
                valueAt += 1;
                finalMessage += ch;
            }
        }
        valueAt = 0;

        if (e) {
            assert finalMessage != null;
            finalMessage = encrypt256(finalMessage, key, salt);

        }
        return finalMessage;
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Please enter message");
        String mssg = scanner.nextLine();
        System.out.println("please select mode rb/b/f/rf");
        String mode = scanner.nextLine();
        System.out.println("Encode or Decode?");
        String eord = scanner.nextLine();
        System.out.println("Please enter salt");
        String slt = scanner.nextLine();
        System.out.println("Please enter key");
        String key = scanner.nextLine();
        String answer = "";

        if (mode.equals("rb")) {
            answer = rBackwards(mssg, slt, eord, key);
        }
        if (mode.equals("b")) {
            answer = backwards(mssg, slt, eord, key);
        }
        if (mode.equals("f")) {
            answer = forwards(mssg, slt, eord, key);
        }
        if (mode.equals("rf")) {
            answer = rForwards(mssg, slt, eord, key);
        }

        System.out.println(answer);

    }

}
