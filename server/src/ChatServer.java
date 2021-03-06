import com.sun.security.ntlm.Server;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;
import java.awt.*;
import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Level;

public class ChatServer implements Runnable {
    private ChatServerThread clients[] = new ChatServerThread[50];
    private ChatServerThread tempClients[] = new ChatServerThread[50];


    private static final String SERVER_KEY_STORE_PASSWORD = "1234ks";
    private static final String SERVER_TRUST_KEY_STORE_PASSWORD = "9876ks";
    private SSLServerSocket serverSocket;
    private Socket s;
    //private ServerSocket server = null;
    private volatile Thread thread = null;
    private int clientCount = 0;
    private int tempClientCount = 0;
    private int port = 54321;

    private MessageDigest md;
    private Map<String, Object> keypair;

    private Logger log = null;
    private FileHandler logFileHd = null;

    private String chatRoomPW = "Comp4017";


    public ChatServer(String ServerPW,int port ) {
        this.port=port;
        this.chatRoomPW = ServerPW;
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

            logFileHd = new FileHandler("./etc/" + "Server" + ".log", false);
            logFileHd.setFormatter(new LogFormatter());
            // get and configure logger
            log = Logger.getLogger("Server");

            log.addHandler(logFileHd);
            log.setUseParentHandlers(false);
            log.setLevel(Level.FINER);
            logFileHd.setLevel(Level.INFO);
            log.info("");
            log.info("");
            log.info("============================================================");
            log.info("Server : Application Starting...");

            start();
        } catch (Exception ioe) {
            System.err.println("Can not bind to port " + port + ": " + ioe.toString());
        }
    }

    public void writelog(String msg) {
        log.info(msg);
    }

    public void run() {
        Thread thisThread = Thread.currentThread();
        while (thread == thisThread) {
            try {
                System.out.println("Waiting for a client ...");
                s = serverSocket.accept();
                addTempThread(s);


                // Do add thread after client auth
//              addThread(s);


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
            log.info("");
            log.info("");
            log.info("============================================================");
            log.info("Server : Application Stopping...");
        }
    }

    private int findClient(int ID) {
        for (int i = 0; i < clientCount; i++)
            if (clients[i].getID() == ID)
                return i;
        return -1;
    }

    private int findTempClient(int ID) {
        for (int i = 0; i < tempClientCount; i++)
            if (tempClients[i].getID() == ID)
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
        for (int i = 0; i <= clientCount; i++) {
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
        for (int i = 0; i < clientCount; i++) {
            clients[i].send(msg);
        }
    }

    public synchronized void sendTo(int ID, Message msg) {
        clients[findClient(ID)].send(msg);
    }


    public synchronized void remove(int ID) {

        log.info("Server : remove ID: " + ID + " .");
        int pos = findClient(ID);

        if (pos >= 0) {
            ChatServerThread toTerminate = clients[pos];
            System.out.println("Removing client thread " + ID + " at " + pos);
            if (pos < clientCount - 1) {
                System.out.println("Client count" + clientCount);
                System.out.println("Adjust client pos");
                for (int i = pos + 1; i < clientCount; i++)
                    clients[i - 1] = clients[i];
            }

            clientCount--;
            try {
                if (pos == 0) {
                    changeAdmin();
                    log.info("Server : Update Admin: " + clients[0].getID() + " .");
                }
                toTerminate.close();
            } catch (IOException ioe) {
                System.out.println("Error closing thread: " + ioe);
            }
            toTerminate.stopThread();
        } else {
            pos = -1;
            pos = findTempClient(ID);

            if (pos >= 0) {
                ChatServerThread toTerminate = tempClients[pos];
                System.out.println("Removing Temp thread " + ID + " at " + pos);
                if (pos < tempClientCount - 1) {
                    System.out.println("Client count" + tempClientCount);
                    System.out.println("Adjust client pos");
                    for (int i = pos + 1; i < tempClientCount; i++)
                        tempClients[i - 1] = tempClients[i];
                }

                tempClientCount--;
                toTerminate.stopThread();
            }
        }
    }

    public synchronized void Authremove(int ID) {
        int pos = findTempClient(ID);
        System.out.println("the pos is : " + pos);
        if (pos >= 0) {
            ChatServerThread toTerminate = tempClients[pos];
            System.out.println("Removing temp client thread " + ID + " at " + pos);
            if (pos < tempClientCount - 1) {
                System.out.println("Client count" + tempClientCount);
                System.out.println("Adjust client pos");
                for (int i = pos + 1; i < tempClientCount; i++)
                    tempClients[i - 1] = tempClients[i];
            }

            tempClientCount--;
        }
    }

    private void addTempThread(Socket socket) {
        if (clientCount < clients.length) {
            System.out.println("Add one Client wait for auth: " + socket);

            tempClients[tempClientCount] = new ChatServerThread(this, socket);

            try {
                tempClients[tempClientCount].open();
                tempClients[tempClientCount].start();
                log.info("Temp Thread : TempClient Created: [" + socket + "].");
                authRequest(tempClientCount);
                tempClientCount++;

            } catch (IOException ioe) {
                System.out.println("Error opening thread: " + ioe);
            }
        } else
            System.out.println("Client refused: maximum " + clients.length + " reached.");
    }


    private void addThread(Socket socket) {
        if (clientCount < clients.length) {
            System.out.println("Client accepted: " + socket);
            clients[clientCount] = new ChatServerThread(this, socket);
            try {
                clients[clientCount].open();
                clients[clientCount].start();
                if (this.clientCount == 0) {
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

    private synchronized void acknowledgeNewClientJoin() {

        try {
            String plainText = "A New Client " + clients[clientCount].getStudendID() + "~" + clients[clientCount].getID() + " Joined";

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

    public synchronized void changeAdmin() {
        try {
            String plainText = "Change Admin";

            String hash = toHash(plainText);

            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));
            // AES
            byte[] cipherText = plainText.getBytes();

            Message msg = new Message(this.getClass().getName(), cipherText, cipherHash, (PublicKey) keypair.get("public"));
            msg.setMessageType(MessageType.changeAdmin);
            clients[0].send(msg);

        } catch (Exception e) {
            System.err.println("Change Admin Error: " + e.toString());
        }
    }

    public synchronized void authRequest(int tempclientID) {
        try {
            String plainText = "Please enter the chat room password";

            String hash = toHash(plainText);

            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));

            byte[] cipherText = plainText.getBytes();

            Message msg = new Message(this.getClass().getName(), cipherText, cipherHash, (PublicKey) keypair.get("public"));
            msg.setMessageType(MessageType.AuthRequest);

            /**** The 0 index just simply send the auth msg to the first one client, you need to modify it to the right client
             *    For each client, you need to generate and one time password and send the password to his email
             *    --------->    So, you need to also store the user email and corressponding one time password for further autherdication
             * ****/
            tempClients[tempclientID].send(msg);

        } catch (Exception e) {
            System.err.println("Auth request Error: ");
            e.printStackTrace();
        }
    }

    public synchronized void authMessage(int tempclientID, String plainText) {
        try {
            //String plainText ="Please enter your email and chat room password";

            String hash = toHash(plainText);

            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));

            byte[] cipherText = plainText.getBytes();

            Message msg = new Message(this.getClass().getName(), cipherText, cipherHash, (PublicKey) keypair.get("public"));
            msg.setMessageType(MessageType.AuthRequest);

            /**** The 0 index just simply send the auth msg to the first one client, you need to modify it to the right client
             *    For each client, you need to generate and one time password and send the password to his email
             *    --------->    So, you need to also store the user email and corressponding one time password for further autherdication
             * ****/
            tempClients[findTempClient(tempclientID)].send(msg);

        } catch (Exception e) {
            System.err.println("Auth request Error: ");
            e.printStackTrace();
        }
    }

    public synchronized void readAuth(int ID, Message msg) {
        try {
            // String hash = toHash(new String(msg.getCipher()));
            String Temp = new String(msg.getCipher());
            //System.out.println("Cipher: " + Temp);
            String myResponse = decryptMessage(Temp, (PrivateKey) keypair.get("private"));

            //  System.out.println(myResponse);
            String hash = toHash(myResponse);

            String plainHash = decryptMessage(msg.getHash(), msg.getPublicKey());
            if (hash.equals(plainHash)) {
//                System.out.println("Server: Auth Msg from: " + msg.getUsername() + " : " + new String(msg.getCipher()));
//                tempClients[findTempClient(ID)].setup(new String(msg.getCipher()));
                System.out.println("Server: Auth Msg from: " + msg.getUsername() + " : " + myResponse);
                tempClients[findTempClient(ID)].setup(myResponse);

                /**************  if auth ok then XXXXXXXXXX ***************/


                /*

                check the client one time password match first

                take out client from tempClient and remove from tempClient

                put it to clients, and then start the normal procedure

                eg: newClientJoin, initadmin, etc..... just like before


                 */


                /**************  if auth ok then XXXXXXXXXX ***************/

            }
        } catch (Exception e) {
            System.err.println(e.toString());
        }
    }

    public synchronized void AuthSuccess(int ID) {
        if (clientCount < clients.length) {
            //System.out.println("Client accepted: " + socket);
            //clients[clientCount] = new ChatServerThread(this, socket);
            clients[clientCount] = tempClients[findTempClient(ID)];
            //tempClients[findTempClient(ID)]=null;
            Authremove(ID);
            try {
                // clients[clientCount].open();
                //clients[clientCount].start();
                if (this.clientCount == 0) {
                    initAdmin();
                }
                acknowledgeNewClientJoin();
                clientCount++;
            } catch (Exception ioe) {
                System.out.println("Error opening thread: " + ioe);
            }
            try {
                String plainText = "AuthSuss";
                String hash = toHash(plainText);
                String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));
                byte[] cipherText = plainText.getBytes();
                Message msg = new Message(this.getClass().getName(), cipherText, cipherHash, (PublicKey) keypair.get("public"));
                msg.setMessageType(MessageType.AuthRequest);

                /**** The 0 index just simply send the auth msg to the first one client, you need to modify it to the right client
                 *    For each client, you need to generate and one time password and send the password to his email
                 *    --------->    So, you need to also store the user email and corressponding one time password for further autherdication
                 * ****/
                clients[clientCount - 1].send(msg);
                System.out.println("Client Count: " + clientCount);
                System.out.println("Temp Count: " + tempClientCount);

            } catch (Exception e) {
                System.err.println("Auth request Error: ");
                e.printStackTrace();
            }
        } else
            System.out.println("Client refused: maximum " + clients.length + " reached.");

    }

    public synchronized void initAdmin() {
        try {
            String plainText = "Init Admin";

            String hash = toHash(plainText);

            String cipherHash = encryptMessage(hash, (PrivateKey) keypair.get("private"));
            // AES
            byte[] cipherText = plainText.getBytes();

            Message msg = new Message(this.getClass().getName(), cipherText, cipherHash, (PublicKey) keypair.get("public"));
            msg.setMessageType(MessageType.initAdmin);
            clients[0].send(msg);
            log.info("Server : Client : [" + clients[0].getID() + "] ---- Init Admin.");

        } catch (Exception e) {
            System.err.println("Init Admin Error: " + e.toString());
        }

    }

    public synchronized void forwardSecKeyRequestToAdmin(Message msg) {
        try {

            clients[0].send(msg);

        } catch (Exception e) {
            System.err.println("forwardSecKeyRequestToAdmin Error: " + e.toString());
        }
    }

    public int getClientCount() {
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

    public String toHash(String plainText) {
        md.update(plainText.getBytes());

        System.out.println("to hash plain content: " + plainText);
        byte[] digest = md.digest();
        //Converting the byte array in to HexString format
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            hexString.append(Integer.toHexString(0xFF & digest[i]));
        }

        String hash = hexString.toString();
        return hash;
    }

    public boolean CheckPw(String PW) {
        return chatRoomPW.equals(PW);
    }
//   public static void main(String args[])
//   {  ChatServer server = null;
//      if (args.length != 1)
//         System.out.println("Usage: java ChatServer port");
//      else
//         server = new ChatServer(Integer.parseInt(args[0]));
//   }
}
