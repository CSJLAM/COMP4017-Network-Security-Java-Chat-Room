import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
    private PublicKey ServerPK;

    private static final String CLIENT_KEY_STORE_PASSWORD = "9876ks";
    private static final String CLIENT_TRUST_KEY_STORE_PASSWORD = "1234ks";

    private SSLSocket sslSocket;

    private boolean isAdmin = false;

    private boolean isAuth = false;


    public ChatClient(String username,String serverName,int serverPort) {
        System.out.println("Establishing connection. Please wait ...");
        this.username = username;
        this.serverName=serverName;
        this.serverPort=serverPort;

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

                    if(this.isAuth) {
                        handleSendMessage(plainText);
                    } else {
                        if (plainText.length() >= 12) {
                            if (plainText.substring(plainText.length() - 11).equals("hkbu.edu.hk")||plainText.indexOf("@")>0) {
                               username=plainText+"~"+ socket.getLocalPort();
                            }
                        }
                        sendUnAuthMessage(plainText);
                    }

                } catch (IOException ioe) {
                    System.out.println("Sending error: " + ioe.getMessage());
                    stop();
                }
            }
    }

    public void sendUnAuthMessage(String plainText) {
        try {

            System.out.println("Send UnAuth Message to server");

            String hash = toHash(plainText);

            // RSA
            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));

            // AES
            //byte[] cipherText = plainText.getBytes();
            String Temp = encryptMessage(plainText,(PublicKey) ServerPK);
            //System.out.println("Temp: "+Temp);
            byte[] cipherText = Temp.getBytes();
            //System.out.println("Cipher: "+cipherText );
            Message msg = new Message(this.username, cipherText, cipherHash, (PublicKey) keypair.get("public"));
            msg.setMessageType(MessageType.AuthResponse);
            objectOutputStream.writeObject(msg);
            objectOutputStream.flush();
//            streamOut.writeUTF(plainText);
//            streamOut.flush();
        } catch (Exception e) {
            System.err.println("Error: " + e.toString());
        }
    }

    public void handleSendMessage(String plainText) {



        try {

            String hash = toHash(plainText);

            // RSA
            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));

            // AES
            byte[] cipherText = secKeyEncryptText(plainText, secKey);

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

        // Send message to server to request secret key
//        requestSecKey();

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

    // Decrypt using RSA private key
    private static String decryptMessage(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }

    // Encrypt using RSA private key
    private static String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    // Encrypt using RSA public key
    private static String encryptMessage(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
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

    public Map<String, Object> getKeypair() {
        return keypair;
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

            this.username = this.username + socket.getLocalPort();

        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    public void readMessage(Message msg){
        try {
            String plainText = secKeyDecryptText(msg.getCipher(), secKey);
            if(toHash(plainText).equals(decryptMessage(msg.getHash(), msg.getPublicKey()))){
                System.out.println(msg.getUsername() + ": " + plainText);
            } else {
                System.err.println("The message have been modified");
            }
        } catch(Exception e){
            System.err.println("Cannot read message: " + e.toString());
        }
    }

    public void readAuthMessage(Message msg){
        try {
            String hash = toHash(new String(msg.getCipher()));
            String plainHash = decryptMessage(msg.getHash(), msg.getPublicKey());
            ServerPK = msg.getPublicKey();
            if (hash.equals(plainHash)) {
                System.out.println("Auth Msg: " + msg.getUsername() + " : " +  new String(msg.getCipher()));
                if((new String(msg.getCipher())).equals("AuthSuss") ){
                    requestSecKey();
                    isAuth=true;
                }
            }
        } catch (Exception e) {
            System.err.println(e.toString());
        }
    }

    public void requestSecKey(){
        String plainText = "Request SecKey";
        String hash = toHash(plainText);
        try {

            // RSA
            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));

            // AES
            byte[] cipherText = plainText.getBytes();

            Message msg = new Message(this.username, cipherText, cipherHash, (PublicKey) keypair.get("public"));
            msg.setMessageType(MessageType.RequestSecKey);
            msg.setReceiver(this.socket.getLocalPort());
            objectOutputStream.writeObject(msg);
            objectOutputStream.flush();


        } catch (Exception e) {
            System.err.println("Error: " + e.toString());
        }
    }

    public void changeAdmin(Message msg) {
        try {
            String hash = toHash(new String(msg.getCipher()));
            String plainHash = decryptMessage(msg.getHash(), msg.getPublicKey());
            if (hash.equals(plainHash)) {
                this.isAdmin = true;
                System.out.println(msg.getUsername() + " : " + new String(msg.getCipher()));
                System.out.println("Now you are admin");

            }
        } catch (Exception e) {
            System.err.println(e.toString());
        }
    }

    public void initAdmin(Message msg) {
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
                System.out.println(msg.getUsername() + " : " +  new String(msg.getCipher()));
            }
        } catch (Exception e) {
            System.err.println(e.toString());
        }
    }

    public boolean getIsAdmin(){
        return this.isAdmin;
    }

    public void setSecKey(SecretKey secKey) {
        this.secKey = secKey;
    }

    public void sendSSecretKey(Message msg) {

        String stringKey = null;

        if (secKey != null) {
            stringKey = Base64.getEncoder().encodeToString(secKey.getEncoded());
        }

        String hash = toHash(stringKey);

        try {

            // RSA
            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));

            String cipherStringKey = encryptMessage(stringKey, (PublicKey) msg.getPublicKey());

            // RSA
            byte[] cipherText = cipherStringKey.getBytes();

            Message secKeyMsg = new Message(this.username, cipherText, cipherHash, (PublicKey) keypair.get("public"));
            secKeyMsg.setMessageType(MessageType.SendSecretKey);
            secKeyMsg.setReceiver(msg.getReceiver());

            objectOutputStream.writeObject(secKeyMsg);
            objectOutputStream.flush();
//            streamOut.writeUTF(plainText);
//            streamOut.flush();
        } catch (Exception e) {
            System.err.println("Error: " + e.toString());
        }
    }

    public void setSecKey(Message msg){
        try {

            String stringKey = decryptMessage(new String(msg.getCipher()), (PrivateKey) keypair.get("private"));

            String hash = toHash(stringKey);

            if(hash.equals(decryptMessage(msg.getHash(), msg.getPublicKey()))){
                byte[] decodedKey = Base64.getDecoder().decode(stringKey);
                SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
                this.secKey = originalKey;
                System.out.println("Secret key have been settle");
            } else {
                System.err.println("Receive wrong secrete key, the system will be turn dowm.");
                System.exit(-1);
            }

        } catch (Exception e){
            System.err.println("Cannot set secret key: " + e.toString());
        }
    }

//   public static void main(String args[])
//   {  ChatClient client = null;
//      if (args.length != 2)
//         System.out.println("Usage: java ChatClient host port");
//      else
//         client = new ChatClient(args[0], Integer.parseInt(args[1]));
//   }
}
