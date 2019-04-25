public class Main {

    public static void main(String[] args) {
        System.out.println("Hello World!");
        if(args.length > 0){
            ChatServer cs = new ChatServer(args[0]);
            System.out.println("Server Password: "+args[0]);
        } else {
            ChatServer cs = new ChatServer("Comp4017");
            System.out.println("Server Password: Comp4017");
        }


    }
}
