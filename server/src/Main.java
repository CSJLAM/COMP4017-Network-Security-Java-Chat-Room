public class Main {

    public static void main(String[] args) {
        System.out.println("Hello World!");
        if(args.length > 0){
            ChatServer cs = new ChatServer(args[0], Integer.parseInt(args[1]));
            System.out.println("Server Password: "+args[0]+" Port: "+ Integer.parseInt(args[1]));
        } else {
            ChatServer cs = new ChatServer("Comp4017",54321);
            System.out.println("Server Password: Comp4017 Port: 54321");
        }


    }
}
