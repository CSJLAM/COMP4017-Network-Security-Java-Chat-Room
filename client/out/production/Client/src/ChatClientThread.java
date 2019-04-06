import javax.net.ssl.SSLSocket;
import java.net.*;
import java.io.*;

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
                    case AssignAdmin:
                        client.setAdmin(msg);
                        break;
                    case SetSecretKey:
                        break;
                    case Client:
                        break;
                    case NewClientJoin:
                        client.NewClientJoin(msg);
                        break;
                    default:
                        break;
                }
                System.out.println("Client 我取得的值:" + msg.getHash());
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

 

