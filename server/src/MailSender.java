import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

public class MailSender {

    public  MailSender(){

    }
    public void SendAuthEmail(String Receiver, String OneTimePassword){
        final String username = "router.jasonlam0725@gmail.com";
        final String password = "zzmavjyrcmyyuutg";
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");

        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password);
                    }
                });

        try {

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("router.jasonlam0725@gmail.com"));
            message.setRecipients(Message.RecipientType.TO,
                    InternetAddress.parse(Receiver));
            message.setSubject("Your One-time password");
            message.setText("This is your Onn-time password "+ OneTimePassword);

            Transport.send(message);

            System.out.println("Email Sent");

        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
    }
}

