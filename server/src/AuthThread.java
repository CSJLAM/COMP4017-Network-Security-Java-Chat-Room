import java.net.*;
import java.io.*;
import java.util.Random;


public class AuthThread extends Thread {
    private ChatServer server = null;
    private Socket socket = null;
    private int ID = -1;
    private DataInputStream streamIn = null;
    private DataOutputStream streamOut = null;
    private volatile Thread thread = null;
    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;
    private String OneTimePassword;
    private MailSender sender = new MailSender();
    private String StudendID;
    private int Status = -1;

    public AuthThread(ChatServer _server, Socket _socket) {
        super();
        server = _server;
        socket = _socket;
        ID = socket.getPort();
        Random rand = new Random();
        OneTimePassword = Integer.toString(rand.nextInt(999999));
        while (OneTimePassword.length() < 6) {
            OneTimePassword = "0" + OneTimePassword;
        }
        System.out.println("Your one time password is " + OneTimePassword);

    }

    public void setup(String ReceiveData) {
        if (Status == -1) {
            if (ReceiveData.length() == 8) {
                String[] StudentIDArray = ReceiveData.split("");
                int[] StudentIDCheck = new int[StudentIDArray.length];
                for (int i = 0; i < StudentIDArray.length; i++) {
                    StudentIDCheck[i] = Integer.parseInt(StudentIDArray[i]);
                }
                int CheckSum = 0;
                for (int i = 0, j = 8; i < StudentIDCheck.length; i++, j--) {
                    CheckSum += StudentIDCheck[i] * j;
                    // System.out.println(StudentIDCheck[i]);
                }
                if (CheckSum % 11 == 0) {
                    Status = 0;//One-time Password Email Sent
                    StudendID = ReceiveData;
                    sender.SendAuthEmail(StudendID + "@life.hkbu.edu.hk", OneTimePassword);
                    server.AuthSendMessage(ID, "We have Send you a one-time password email on your BU Email: " + StudendID + "@life.hkbu.edu.hk\nPlease input the one time password");
                } else {
                    //System.out.println("Fail");
                    server.AuthSendMessage(ID, "Your ID is not correct!\nPlease enter your HKBU Student ID");
                }

            } else {
                server.AuthSendMessage(ID, "Your ID is not correct!\nPlease enter your HKBU Student ID");
            }
        } else if (Status == 0) {
            if (ReceiveData.length() == 6) {
                if (ReceiveData.equals(OneTimePassword)) {
                    System.out.println("correct");
                    server.AuthSuccess(ID, socket, StudendID);
                } else {
                    System.out.println("Wrong");
                }
            } else {
                System.out.println("Wrong");
            }
        }
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
                    case SendAuthID:

                        server.SendAuthID(ID, msg);
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

    public ChatServer GetThreadServer() {
        return server;
    }


}
