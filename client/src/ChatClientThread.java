import javax.net.ssl.SSLSocket;
import java.net.*;
import java.io.*;
import java.security.PublicKey;

public class ChatClientThread extends Thread {
    private SSLSocket socket = null;
    private ChatClient client = null;
    private DataInputStream streamIn = null;
    private ObjectInputStream objectInputStream;
    private volatile Thread thread = null;

    public ChatClientThread(ChatClient _client, SSLSocket _socket) {
        client = _client;
        socket = _socket;
        open();
        start();
    }

    public void open() {
        try {
            streamIn = new DataInputStream(socket.getInputStream());
            objectInputStream = new ObjectInputStream(socket.getInputStream());
        } catch (IOException ioe) {
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
    }

    public void close() {
        try {
            if (streamIn != null) streamIn.close();
        } catch (IOException ioe) {
            System.out.println("Error closing input stream: " + ioe);
        }
    }

    public void run() {
        Thread thisThread = Thread.currentThread();
        while (thread == thisThread) {
            try {
                Message msg = (Message) objectInputStream.readObject();
                switch (msg.getMessageType()) {
                    case initAdmin:
                        client.initAdmin(msg);
                        break;
                    case SendSecretKey:
                        client.setSecKey(msg);
                        break;
                    case Client:
                        client.readMessage(msg);
                        break;
                    case NewClientJoin:
                        client.NewClientJoin(msg);
                        break;
                    case changeAdmin:
                        client.changeAdmin(msg);
                        break;
                    case RequestSecKey:
                        if(client.getIsAdmin()){

                            if(msg.getReceiver() != socket.getLocalPort() && !msg.getPublicKey().equals((PublicKey)client.getKeypair().get("public"))){

                                client.sendSSecretKey(msg);
                            }

                        }
                        break;
                    case AuthEmail:
                        client.AuthEmail(msg);
                        break;
                    case SendAuthID:
                        client.SendAuthID(msg);
                    default:
                        break;
                }
                // System.out.println("Client 我取得的值:" + msg.getMessageType() + " ; " + msg.getHash());
//            client.handle(streamIn.readUTF());
            } catch (Exception e) {
                System.out.println("Listening error: " + e.getMessage());
                client.stop();
            }
        }
    }

    public void start() {
        thread = new Thread(this);

        thread.start();
    }

    public void stopThread() {
        thread = null;
    }
}

 

