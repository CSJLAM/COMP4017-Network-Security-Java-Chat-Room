import java.net.*;
import java.io.*;
import java.util.Random;

public class ChatServerThread extends Thread {
    private ChatServer server = null;
    private Socket socket = null;
    private int ID = -1;
    private DataInputStream streamIn = null;
    private DataOutputStream streamOut = null;
    private volatile Thread thread = null;
    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;
    private int Status = -1;
    private String OneTimePassword;
    private MailSender sender = new MailSender();
    private String StudendID;

    public ChatServerThread(ChatServer _server, Socket _socket) {
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
            if (server.CheckPw(ReceiveData)) {
                Status = 0;
                server.authMessage(ID, "Please enter your HKBU email.");
            } else {
                server.authMessage(ID, "The password is not correct!\nPlease enter the chat room password");
            }
        } else if (Status == 0) {
//            if (ReceiveData.length() == 8) {
//                String[] StudentIDArray = ReceiveData.split("");
//                int[] StudentIDCheck = new int[StudentIDArray.length];
//                for (int i = 0; i < StudentIDArray.length; i++) {
//                    StudentIDCheck[i] = Integer.parseInt(StudentIDArray[i]);
//                }
//                int CheckSum = 0;
//                for (int i = 0, j = 8; i < StudentIDCheck.length; i++, j--) {
//                    CheckSum += StudentIDCheck[i] * j;
//                    // System.out.println(StudentIDCheck[i]);
//                }
//                if (CheckSum % 11 == 0) {
//                    Status = 1;//One-time Password Email Sent
//                    StudendID = ReceiveData;
//                    sender.SendAuthEmail(StudendID + "@life.hkbu.edu.hk", OneTimePassword);
//                    server.authMessage(ID, "We have Send you a one-time password email on your BU Email: " + StudendID + "@life.hkbu.edu.hk\nPlease enter the one time password");
//                } else {
//                    //System.out.println("Fail");
//                    server.authMessage(ID, "Your ID is not correct!\nPlease enter your HKBU Student ID");
//                }
//
//            }
            if (ReceiveData.length() >= 12) {
                if (ReceiveData.substring(ReceiveData.length() - 11).equals("hkbu.edu.hk")&&ReceiveData.indexOf("@")>0) {
                    Status = 1;//One-time Password Email Sent
                    StudendID = ReceiveData;
                    sender.SendAuthEmail(StudendID, OneTimePassword);
                    server.authMessage(ID, "We have Send you a one-time password email on your BU Email: " + StudendID + "\nPlease enter the one time password");
                } else {
                    server.authMessage(ID, "Your ID is not correct!\nPlease enter your HKBU Student ID");
                }

            } else {
                server.authMessage(ID, "Your ID is not correct!\nPlease enter your HKBU Student ID");
            }
        } else if (Status == 1) {
            if (ReceiveData.length() == 6) {
                if (ReceiveData.equals(OneTimePassword)) {
                    //System.out.println("correct");
                    Status = 2;
                    server.AuthSuccess(ID);
                    server.writelog("Client Thread : Client Created: [" + socket +"Client Name is:"+StudendID +"].");
                    server.writelog("Temp Thread : Temp Removed: [" + socket + "].");
                } else {
                    //System.out.println("Wrong");
                    server.authMessage(ID, "Your One-time password is not correct!\nPlease enter the password.");
                }
            } else {
                // System.out.println("Wrong");
                server.authMessage(ID, "Your One-time password is not correct!\nPlease enter the password.");
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
                        server.writelog("Client Thread : Client : [" + socket +"Client Name is:"+StudendID +"] ---- Client RequestSecKey.");
                        System.out.println("Reqest from client: " + new String(msg.getCipher()));
                        server.forwardSecKeyRequestToAdmin(msg);
                        break;
                    case SendSecretKey:
                        server.writelog("Client Thread : Client : [" + socket +"Client Name is:"+StudendID +"] ---- Client SendSecretKey.");
                        server.sendTo(msg.getReceiver(), msg);
                        break;
                    case AuthResponse:
                        server.readAuth(ID, msg);
                        break;
                    default:
                        server.writelog("Client Thread : Client : [" + socket +"Client Name is:"+StudendID +"] ---- Client Send Message Default.");
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
