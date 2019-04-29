public class Main {

    public static void main(String[] args) {
        if(args.length > 0){
            ChatClient cc = new ChatClient("Guest",args[0],Integer.parseInt(args[1]));
            System.out.println("Hello Guest!");
            System.out.println("The server you connect at: "+args[0]+" and the port is: "+Integer.parseInt(args[1])+".");
        } else {
            ChatClient cc = new ChatClient("Guest","localhost",54321);
            System.out.println("Hello Guest!");
            System.out.println("The server you connect at: localhost and the port is: 54321.");
        }
    }
}
