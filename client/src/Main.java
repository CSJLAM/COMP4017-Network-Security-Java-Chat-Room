public class Main {

    public static void main(String[] args) {
        if(args.length > 0){
            ChatClient cc = new ChatClient(args[0]);
        } else {
            ChatClient cc = new ChatClient("Guest");
            System.out.println("Hello Guest!");
        }
    }
}
