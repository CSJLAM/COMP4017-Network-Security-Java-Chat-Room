import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;
import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class ChatServer implements Runnable {
    private ChatServerThread clients[] = new ChatServerThread[50];
    private AuthThread Auth[] = new AuthThread[50];
    private static final String SERVER_KEY_STORE_PASSWORD       = "1234ks";
    private static final String SERVER_TRUST_KEY_STORE_PASSWORD = "9876ks";
    private SSLServerSocket serverSocket;
    private Socket s;
    //private ServerSocket server = null;
    private volatile Thread thread = null;
    private int clientCount = 0;
    private int authCount = 0;
    private int port = 54321;

    private MessageDigest md;
    private Map<String, Object> keypair;



    public ChatServer() {
        try {
            System.out.println("Binding to port " + port + ", please wait  ...");
            SSLContext ctx = SSLContext.getInstance("SSL");

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");

            KeyStore ks = KeyStore.getInstance("JKS");
            KeyStore tks = KeyStore.getInstance("JKS");

            ks.load(new FileInputStream("./src/SSL/kserver.keystore"), SERVER_KEY_STORE_PASSWORD.toCharArray());
            tks.load(new FileInputStream("./src/SSL/trustserver.keystore"), SERVER_TRUST_KEY_STORE_PASSWORD.toCharArray());

            kmf.init(ks, SERVER_KEY_STORE_PASSWORD.toCharArray());
            tmf.init(tks);

            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            serverSocket = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(port);
            serverSocket.setNeedClientAuth(true);
            System.out.println("Server started: " + serverSocket);

            md = MessageDigest.getInstance("SHA-512");
            keypair = getRSAKeys();





            start();
        } catch (Exception ioe) {
            System.err.println("Can not bind to port " + port + ": " + ioe.toString());
        }
    }

    public void run() {
        Thread thisThread = Thread.currentThread();
        while (thread == thisThread) {
            try {
                System.out.println("Waiting for a client ...");
                s = serverSocket.accept();
                //addThread(s);
                addAuth(s);
            } catch (IOException ioe) {
                System.out.println("Server accept error: " + ioe);
                stop();
            }
        }
    }

    public void start() {
        if (thread == null) {
            thread = new Thread(this);
            thread.start();
        }
    }

    public void stop() {
        if (thread != null) {
            thread = null;
        }
    }

    private int findClient(int ID) {
        for (int i = 0; i < clientCount; i++)
            if (clients[i].getID() == ID)
                return i;
        return -1;
    }
    private  int findAuth(int ID){
        for (int i = 0; i<authCount; i++)
            if(Auth[i].getID() == ID)
                return i;
            return -1;
    }

    public synchronized void handle(Message msg) {
//        if (input.equals(".bye")) {
//            clients[findClient(ID)].send(".bye");
//            remove(ID);
//        } else
//            for (int i = 0; i < clientCount; i++)
//                clients[i].send(ID + ": " + input);
        for (int i = 0; i <= clientCount; i++){
            clients[i].send(msg);
        }
    }

    public synchronized void handle(int ID, Message msg) {
//        if (input.equals(".bye")) {
//            clients[findClient(ID)].send(".bye");
//            remove(ID);
//        } else
//            for (int i = 0; i < clientCount; i++)
//                clients[i].send(ID + ": " + input);
        for (int i = 0; i < clientCount; i++){
            clients[i].send(msg);
        }
    }

    public synchronized void sendTo(int ID, Message msg) {
        clients[findClient(ID)].send(msg);
    }


    public synchronized void removeAuth(int ID) {
        int pos = findAuth(ID);
        if (pos >= 0) {
            AuthThread toTerminate = Auth[pos];
            System.out.println("Removing client thread " + ID + " at " + pos);
            if (pos < authCount - 1){
                System.out.println("Client count" + authCount);
                System.out.println("Adjust client pos");
                for (int i = pos + 1; i < authCount; i++)
                    Auth[i - 1] = Auth[i];
            }

            authCount--;

            toTerminate.stopThread();
        }
    }
    public synchronized void remove(int ID) {
        int pos = findClient(ID);
        if (pos >= 0) {
            ChatServerThread toTerminate = clients[pos];
            System.out.println("Removing client thread " + ID + " at " + pos);
            if (pos < clientCount - 1){
                System.out.println("Client count" + clientCount);
                System.out.println("Adjust client pos");
                for (int i = pos + 1; i < clientCount; i++)
                    clients[i - 1] = clients[i];
            }

            clientCount--;
            try {
                if(pos == 0){
                    changeAdmin();
                }
                toTerminate.close();
            } catch (IOException ioe) {
                System.out.println("Error closing thread: " + ioe);
            }
            toTerminate.stopThread();
        }
    }

    private void addAuth(Socket socket){
        if (authCount < Auth.length) {
            System.out.println("Auth Client accepted: " + socket);
            Auth[authCount] = new AuthThread(this, socket);
            try {
                Auth[authCount].open();
                Auth[authCount].start();
                if(this.authCount == 0){
                    //initAdmin();
                }
                AuthEmail(authCount);
                //acknowledgeNewClientJoin();
                authCount++;
            } catch (IOException ioe) {
                System.out.println("Error opening thread: " + ioe);
            }
        } else
            System.out.println("Auth Client refused: maximum " + Auth.length + " reached.");
    }
    private void addThread(Socket socket) {
        if (clientCount < clients.length) {
            System.out.println("Client accepted: " + socket);
            clients[clientCount] = new ChatServerThread(this, socket);
            try {
                clients[clientCount].open();
                clients[clientCount].start();
                if(this.clientCount == 0){
                    initAdmin();
                }
                acknowledgeNewClientJoin();
                clientCount++;
            } catch (IOException ioe) {
                System.out.println("Error opening thread: " + ioe);
            }
        } else
            System.out.println("Client refused: maximum " + clients.length + " reached.");
    }

    private synchronized void acknowledgeNewClientJoin(){

        try {
            String plainText = "A New Client " +  clients[clientCount].getID() + " Joined";

            String hash = toHash(plainText);

            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));
            // AES
            byte[] cipherText = plainText.getBytes();

            Message msg = new Message(this.getClass().getName(), cipherText, cipherHash, (PublicKey) keypair.get("public"));
            msg.setMessageType(MessageType.NewClientJoin);
            msg.setReceiver(clients[clientCount].getID());
            handle(msg);

        } catch (Exception e) {
            System.err.println(e.toString());
        }
    }

    public synchronized void changeAdmin(){
        try {
            String plainText ="Change Admin";

            String hash = toHash(plainText);

            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));
            // AES
            byte[] cipherText = plainText.getBytes();

            Message msg = new Message(this.getClass().getName(), cipherText, cipherHash, (PublicKey) keypair.get("public"));
            msg.setMessageType(MessageType.changeAdmin);
            clients[0].send(msg);

        } catch (Exception e){
            System.err.println("Change Admin Error: " + e.toString());
        }
    }
    public synchronized  void  AuthEmail(int Count){
        try{
            //String plainText ="Auth Email";
            String plainText ="Please enter your HKBU Student ID";
            String hash = toHash(plainText);

            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));
            // AES
            byte[] cipherText = plainText.getBytes();

            Message msg = new Message(this.getClass().getName(), cipherText, cipherHash, (PublicKey) keypair.get("public"));
            msg.setMessageType(MessageType.AuthEmail);
            Auth[Count].send(msg);
        } catch (Exception e){
            System.err.println("Auth email error:"+ e.toString());
        }
}
public synchronized void AuthSuccess(int ID, Socket socket,String StudendID){
    //removeAuth(ID);
       // addThread(socket);
    if (clientCount < clients.length) {
        System.out.println("Client accepted: " + socket);
        clients[clientCount] = new ChatServerThread(Auth[findAuth(ID)].GetThreadServer(), socket);
        try {
            clients[clientCount].open();
            clients[clientCount].start();
            if(this.clientCount == 0){
                initAdmin();
            }
            acknowledgeNewClientJoin();
            clientCount++;
        } catch (IOException ioe) {
            System.out.println("Error opening thread: " + ioe);
        }
    } else
        System.out.println("Client refused: maximum " + clients.length + " reached.");

}
public synchronized void  AuthSendMessage(int ID, String plainText){
        try{
            //String plainText ="Auth Email";
           // String plainText ="Please enter your HKBU Student ID";
            String hash = toHash(plainText);

            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));
            // AES
            byte[] cipherText = plainText.getBytes();

            Message msg = new Message(this.getClass().getName(), cipherText, cipherHash, (PublicKey) keypair.get("public"));
            msg.setMessageType(MessageType.SendAuthID);
            Auth[findAuth(ID)].send(msg);
        } catch (Exception e){
            System.err.println("Auth email error:"+ e.toString());
        }
    }


    public synchronized void initAdmin(){
        try {
            String plainText ="Init Admin";

            String hash = toHash(plainText);

            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));
            // AES
            byte[] cipherText = plainText.getBytes();

            Message msg = new Message(this.getClass().getName(), cipherText, cipherHash, (PublicKey) keypair.get("public"));
            msg.setMessageType(MessageType.initAdmin);
            clients[0].send(msg);

        } catch (Exception e){
            System.err.println("Init Admin Error: " + e.toString());
        }

    }

    public synchronized void forwardSecKeyRequestToAdmin(Message msg) {
        try {

            clients[0].send(msg);

        } catch (Exception e){
            System.err.println("Init Admin Error: " + e.toString());
        }
    }

    public void SendAuthID(int ID, Message msg) {
        try {
            String hash = toHash(new String(msg.getCipher()));
            String plainHash = decryptMessage(msg.getHash(), msg.getPublicKey());
            if (hash.equals(plainHash)) {

                //secKey = getSecretEncryptionKey();
                System.out.println(msg.getUsername() + " : " + new String(msg.getCipher()));
                Auth[findAuth(ID)].setup(new String(msg.getCipher()));
            }
        } catch (Exception e) {
            System.err.println(e.toString());
        }
    }

    public int getClientCount(){
        return this.clientCount;
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
     * @return
     * @throws Exception
     */
    public static SecretKey getSecretEncryptionKey() throws Exception{
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        return secKey;
    }

    /**
     * Encrypts plainText in AES using the secret key
     * @param plainText
     * @param secKey
     * @return
     * @throws Exception
     */
    public static byte[] secKeyEncryptText(String plainText,SecretKey secKey) throws Exception{
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return byteCipherText;
    }

    /**
     * Decrypts encrypted byte array using the key used for encryption.
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
     * @param hash
     * @return
     */
    private static String  bytesToHex(byte[] hash) {
        return DatatypeConverter.printHexBinary(hash);
    }

    public String toHash(String plainText) {
        md.update(plainText.getBytes());

        System.out.println("plain content: " + plainText);
        byte[] digest = md.digest();
        //Converting the byte array in to HexString format
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            hexString.append(Integer.toHexString(0xFF & digest[i]));
        }

        String hash = hexString.toString();
        return hash;
    }
//   public static void main(String args[])
//   {  ChatServer server = null;
//      if (args.length != 1)
//         System.out.println("Usage: java ChatServer port");
//      else
//         server = new ChatServer(Integer.parseInt(args[0]));
//   }
}
