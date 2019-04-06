import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;


public class ChatClient implements Runnable {
    private SSLSocket socket = null;
    private volatile Thread thread = null;
    private BufferedReader console = null;
    private DataOutputStream streamOut = null;
    private ObjectOutputStream objectOutputStream;
    private ChatClientThread client = null;
    private int serverPort = 54321;
    private String serverName = "localhost";
    private MessageDigest md;
    private Map<String, Object> keypair;
    private String username;
    private SecretKey secKey;

    private static final String CLIENT_KEY_STORE_PASSWORD = "9876ks";
    private static final String CLIENT_TRUST_KEY_STORE_PASSWORD = "1234ks";

    private SSLSocket sslSocket;

    private boolean isAdmin = false;


    public ChatClient(String username) {
        System.out.println("Establishing connection. Please wait ...");
        this.username = username;

        try {

            keypair = getRSAKeys();

            md = MessageDigest.getInstance("SHA-512");
//            socket = new Socket(serverName, serverPort);
            init();
            System.out.println("Connected: " + socket);

            start();
        } catch (Exception e) {
            System.err.println("Error: " + e.toString());
        }
    }

    public void run() {
        Thread thisThread = Thread.currentThread();
        while (thread == thisThread)
            while (thread != null) {
                try {
                    String plainText = console.readLine();

                    handleSendMessage(plainText);


                } catch (IOException ioe) {
                    System.out.println("Sending error: " + ioe.getMessage());
                    stop();
                }
            }
    }

    public void handleSendMessage(String plainText) {

        String hash = toHash(plainText);
        System.out.println("Hash: " + hash);


        try {

            // RSA
            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));

            // AES
            byte[] cipherText = secKeyEncryptText(plainText, secKey);

            System.out.println("Cipher: " + bytesToHex(cipherText));

//            System.out.println("decypt text: " + secKeyDecryptText(cipherText, secKey));

            Message msg = new Message(this.username, cipherText, cipherHash, (PublicKey) keypair.get("public"));

            objectOutputStream.writeObject(msg);
            objectOutputStream.flush();
//            streamOut.writeUTF(plainText);
//            streamOut.flush();
        } catch (Exception e) {
            System.err.println("Error: " + e.toString());
        }

    }

    public String toHash(String plainText) {
        md.update(plainText.getBytes());
        byte[] digest = md.digest();
        //Converting the byte array in to HexString format
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            hexString.append(Integer.toHexString(0xFF & digest[i]));
        }

        String hash = hexString.toString();
        return hash;
    }

    public void handle(String msg) {
        if (msg.equals(".bye")) {
            System.out.println("Good bye. Press RETURN to exit ...");
            stop();
        } else
            System.out.println(msg);
    }

    public void start() throws IOException {
        console = new BufferedReader(new InputStreamReader(System.in));
        streamOut = new DataOutputStream(socket.getOutputStream());
        objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        if (thread == null) {
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);
            thread.start();
        }
    }

    public void stop() {
        if (thread != null) {
            thread = null;
        }
        try {
            if (console != null) console.close();
            if (streamOut != null) streamOut.close();
            if (socket != null) socket.close();
        } catch (IOException ioe) {
            System.out.println("Error closing ...");
        }
        client.close();
        client.stopThread();
    }

    private static Map<String, Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Map<String, Object> keys = new HashMap<String, Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }

    // Decrypt using RSA public key
    private static String decryptMessage(String encryptedText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }

    // Encrypt using RSA private key
    private static String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    /**
     * gets the AES encryption key. In your actual programs, this should be safely
     * stored.
     *
     * @return
     * @throws Exception
     */
    public static SecretKey getSecretEncryptionKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        return secKey;
    }

    /**
     * Encrypts plainText in AES using the secret key
     *
     * @param plainText
     * @param secKey
     * @return
     * @throws Exception
     */
    public static byte[] secKeyEncryptText(String plainText, SecretKey secKey) throws Exception {
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return byteCipherText;
    }

    /**
     * Decrypts encrypted byte array using the key used for encryption.
     *
     * @param byteCipherText
     * @param secKey
     * @return
     * @throws Exception
     */
    public static String secKeyDecryptText(byte[] byteCipherText, SecretKey secKey) throws Exception {
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePlainText = aesCipher.doFinal(byteCipherText);
        return new String(bytePlainText);
    }

    /**
     * Convert a binary byte array into readable hex form
     *
     * @param hash
     * @return
     */
    private static String bytesToHex(byte[] hash) {
        return DatatypeConverter.printHexBinary(hash);
    }

    private void init() {
        try {
            SSLContext ctx = SSLContext.getInstance("SSL");

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");

            KeyStore ks = KeyStore.getInstance("JKS");
            KeyStore tks = KeyStore.getInstance("JKS");

            ks.load(new FileInputStream("./src/SSL/kclient.keystore"), CLIENT_KEY_STORE_PASSWORD.toCharArray());
            tks.load(new FileInputStream("./src/SSL/trustclient.keystore"), CLIENT_TRUST_KEY_STORE_PASSWORD.toCharArray());

            kmf.init(ks, CLIENT_KEY_STORE_PASSWORD.toCharArray());
            tmf.init(tks);

            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            socket = (SSLSocket) ctx.getSocketFactory().createSocket(serverName, serverPort);
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    public void setAdmin(Message msg) {
        try {
            String hash = toHash(new String(msg.getCipher()));
            String plainHash = decryptMessage(msg.getHash(), msg.getPublicKey());
            if (hash.equals(plainHash)) {
                this.isAdmin = true;
                secKey = getSecretEncryptionKey();
                System.out.println(msg.getUsername() + " : " + new String(msg.getCipher()));
            }
        } catch (Exception e) {
            System.err.println(e.toString());
        }
    }

    public void NewClientJoin(Message msg) {
        try {
            String hash = toHash(new String(msg.getCipher()));
            String plainHash = decryptMessage(msg.getHash(), msg.getPublicKey());
            if (hash.equals(plainHash)) {
                if (isAdmin) {
                    sendSSecretKey(msg.getReceiver());
                }
                System.out.println(msg.getUsername() + " : " + msg.getCipher());
            }
        } catch (Exception e) {
            System.err.println(e.toString());
        }
    }

    public void sendSSecretKey(int receiverID) {
        String stringKey = null;
        if (secKey != null) {
            stringKey = Base64.getEncoder().encodeToString(secKey.getEncoded());
        }
        System.out.println(stringKey);

//
//        String hash = toHash(plainText);
//        System.out.println("Hash: " + hash);
//        try {
//
//            // RSA
//            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));
//
//            // AES
//            byte[] cipherText = secKeyEncryptText(plainText, secKey);
//
//            System.out.println("Cipher: " + bytesToHex(cipherText));
//
////            System.out.println("decypt text: " + secKeyDecryptText(cipherText, secKey));
//
//            Message msg = new Message(this.username, cipherText, cipherHash, (PublicKey) keypair.get("public"));
//
//            objectOutputStream.writeObject(msg);
//            objectOutputStream.flush();
////            streamOut.writeUTF(plainText);
////            streamOut.flush();
//        } catch (Exception e) {
//            System.err.println("Error: " + e.toString());
//        }
    }

//   public static void main(String args[])
//   {  ChatClient client = null;
//      if (args.length != 2)
//         System.out.println("Usage: java ChatClient host port");
//      else
//         client = new ChatClient(args[0], Integer.parseInt(args[1]));
//   }
}
