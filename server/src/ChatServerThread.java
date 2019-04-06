import java.net.*;
import java.io.*;

public class ChatServerThread extends Thread {
    private ChatServer server = null;
    private Socket socket = null;
    private int ID = -1;
    private DataInputStream streamIn = null;
    private DataOutputStream streamOut = null;
    private volatile Thread thread = null;
    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;

    public ChatServerThread(ChatServer _server, Socket _socket) {
        super();
        server = _server;
        socket = _socket;
        ID = socket.getPort();

    }

    public void send(Message msg) {
        try {
//            streamOut.writeUTF(msg);
//            streamOut.flush();
            objectOutputStream.writeObject(msg);
            objectOutputStream.flush();
        } catch (IOException ioe) {
            System.out.println(ID + " ERROR sending: " + ioe.getMessage());
            server.remove(ID);
            stopThread();
        }
    }

    public int getID() {
        return ID;
    }

    public void run() {
        System.out.println("Server Thread " + ID + " running.");
        Thread thisThread = Thread.currentThread();
        while (thread == thisThread) {
            try {

                Message msg = (Message) objectInputStream.readObject();

                System.out.println("我取得的值:" + msg.getUsername());

                switch (msg.getMessageType()) {
                    case RequestSecKey:
                        System.out.println("Reqest from client: " + new String(msg.getCipher()));
                        server.forwardSecKeyRequestToAdmin(msg);
                        break;
                    case SendSecretKey:
                        server.sendTo(msg.getReceiver(), msg);
                        break;
                    default:
                        server.handle(ID, msg);
                        break;
                }


            } catch (Exception e) {
                System.out.println(ID + " ERROR reading: " + e.getMessage());
                server.remove(ID);
                stopThread();
            }
        }
    }

    public void open() throws IOException {
        streamIn = new DataInputStream(new
                BufferedInputStream(socket.getInputStream()));
        objectInputStream = new
                ObjectInputStream(socket.getInputStream());
        streamOut = new DataOutputStream(new
                BufferedOutputStream(socket.getOutputStream()));
        objectOutputStream = new
                ObjectOutputStream(socket.getOutputStream());

    }

    public void close() throws IOException {
        if (socket != null) socket.close();
        if (streamIn != null) streamIn.close();
        if (streamOut != null) streamOut.close();
    }

    public void start() {
        thread = new Thread(this);
        thread.start();
    }

    public void stopThread() {
        thread = null;
    }
}
