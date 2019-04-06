import javax.crypto.SecretKey;
import java.security.PublicKey;



enum MessageType {
    Client, AssignAdmin, SetSecretKey, NewClientJoin
}


public class Message implements java.io.Serializable{
    private String username;
    private byte[] cipher;
    private String hash;
    private PublicKey publicKey;

    private MessageType messageType = MessageType.Client;

    private int receiver;



    Message(String username, byte[] cipher, String hash, PublicKey publicKey){
        this.setUsername(username);
        this.setCipher(cipher);
        this.setHash(hash);
        this.setPublicKey(publicKey);
    }

    public int getReceiver() {
        return receiver;
    }

    public void setReceiver(int receiver) {
        this.receiver = receiver;
    }

    public MessageType getMessageType() {
        return messageType;
    }

    public void setMessageType(MessageType messageType) {
        this.messageType = messageType;
    }

    public byte[] getCipher() {
        return cipher;
    }

    public void setCipher(byte[] cipher) {
        this.cipher = cipher;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username){
        this.username = username;
    }


}
