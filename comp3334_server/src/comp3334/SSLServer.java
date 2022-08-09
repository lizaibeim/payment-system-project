package comp3334;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class SSLServer extends Thread {
    private static SHA sha;
    private Socket socket;
    private static String publicKey_server; //the server's public key, will be transfer to client
    private static String privateKey_server; //the server's private key, keep by server and decrypt message sent from client
    private static String publicKey_client; //the client's public key, used to encrypt message sent to client
    private static Map<String, String> userpassword;
  
    public SSLServer(Socket socket) {
        //initialize server for each socket session to generate server public key and private key for RSA alogrithm
        this.sha = new SHA();
        this.socket = socket;

        userpassword = new HashMap<>();
        userpassword.put("Alice","12345");


    }
  
    public void run() {
        try {
            Map<String, String> keyMap = RSA.createKeys(1024);
            publicKey_server = keyMap.get("publicKey");
            privateKey_server = keyMap.get("privateKey");
            //System.out.println("Public key for server: \n\r" + publicKey_server);
            //System.out.println("Private key for server: \n\r" + privateKey_server);

            PrintWriter writer = new PrintWriter(socket.getOutputStream());
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            //send server's public key to client, assume it as secure
            writer.println(publicKey_server);
            writer.flush();

            //get client's public key, assume it as secure
            publicKey_client = reader.readLine();
            //System.out.print("Public key for client: \n\r"+publicKey_client+"\n");

        	Scanner scan = new Scanner(System.in);
        	System.out.print("Set transaction amount: ");
        	String content;
        	content = scan.next();

            //set the first request to client (Transcation amount verify)
            writer.println(dataEncrypt(content, sha));
            writer.flush();

            //Waif for the first response from client, whether the amount is sent correctly or not
            while(true) {
                String response = reader.readLine();
                String[] plaintext = dataDecrypt(response);
                if(plaintext[1].equals("true") && plaintext[0].substring(4).equals("true")){
                    //System.out.println("The content is transferred correctly");
                    break;
                } else { //retransfer the data agian
                    writer.println(dataEncrypt(content,sha));
                    writer.flush();
                }
            }


            //Get the first message sent from client and check its integrity
            while (true) {
                //Read the first message from client, which is password
                String password = reader.readLine();
                //System.out.println("Ciphertext: [ " + password + " ]");
                String[] a = dataDecrypt(password);
                if(a[1].equals("true")){
                    //the data integrity is guaranteed
                    //System.out.println("The content is secure:" + a[0].substring(4));
                    //check whether the password is correct or not
                    if(!(a[0].substring(4).equals(userpassword.get("Alice")))){
                        writer.println(dataEncrypt("wrong",sha));
                        writer.flush();
                        continue;
                    }
                    writer.println(dataEncrypt("true",sha));
                    writer.flush();
                    break;
                }else {
                    //the data has been changed
                    //System.out.println("The content is not secure.");
                    //ask for retransferring from server
                    writer.println(dataEncrypt("false",sha));
                    writer.flush();
                }

            }
            System.out.print("Transcation Done!!!");
            writer.close();  
            socket.close();  
        } catch (Exception e) {
  
        }  
    }  
  
    private static String SERVER_KEY_STORE = "/Library/Java/JavaVirtualMachines/jdk1.8.0_101.jdk/Contents/Home/bin/server_ks";
    private static String SERVER_KEY_STORE_PASSWORD = "123123";

    //get the decrypted message and check its integrity
    private static String[] dataDecrypt(String ciphertext) throws Exception{
        //System.out.println("\n======================Start Decryption======================");
        //decrypt the message first by RSA, then do hash for content to check data integrity
        String digested = RSA.privateDecrypt(ciphertext, RSA.getPrivateKey(privateKey_server));
        //System.out.println("Digested data decrypted from RSA 1024: [ " + digested + " ]");

        //split the digested
        String hash = digested.substring(5,37);
        String content = digested.substring(45);
        String checkout = sha.sha1(content);

        if (checkout.equals(hash)) {
            String [] a = {content,"true"};
            //System.out.println("Content with timestamp: " + a[0] + " Integrity: " + a[1]);
            return a;
        } else {
            String [] a = {content,"false"};
            //System.out.println("Content with timestamp: " + a[0] + " Integrity: " + a[1]);
            return a;
        }
    }

    private static String dataEncrypt(String data, SHA sha) throws Exception{
        //System.out.println("\n======================Start Encryption======================");
        //cancatenate teh data with seconds
        java.sql.Timestamp time= new java.sql.Timestamp(System.currentTimeMillis());
        int seconds = strToSeconds(time.toString().substring(14,19));
        //System.out.println("Current time: " + time + " " + seconds);
        String s = String.format("%04d",seconds);
        data = s+data;

        //digest the data with sha1 algorithm
        String hash = sha.sha1(data);
        String digested = "Hash:" + hash + "Content:" + data;
        //encrypt the digested data packet via RSA algorithmn with publicKey_client
        //System.out.println("Digested Data(Hashvalue and Content): [ " + digested + " ]");
        String ciphertext = RSA.publicEncrypt(digested, RSA.getPublicKey(publicKey_client));
        //System.out.println("Hashed Data encrypted with RSA 512: [ " + ciphertext + " ]");

        return ciphertext;
    }


    //convert the time xx:xx to int to indicate seconds
    public static int strToSeconds(String str) {
        String[] strs = str.split(":");
        if(strs.length != 2) {
            System.out.println("unvalid input");
            return -1;
        }
        int minute = Integer.valueOf(strs[0]);
        int second = Integer.valueOf(strs[1]);
        return (minute * 60 + second);
    }

    public static void transcation(ServerSocket _socket) throws Exception{
        SSLServer server = new SSLServer(_socket.accept());
        server.start();
        try {
            server.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {  
        System.setProperty("javax.net.ssl.trustStore", SERVER_KEY_STORE);
        //System.setProperty("javax.net.debug", "ssl,handshake");
        SSLContext context = SSLContext.getInstance("TLS");  
          
        KeyStore ks = KeyStore.getInstance("jceks");  
        ks.load(new FileInputStream(SERVER_KEY_STORE), null);  
        KeyManagerFactory kf = KeyManagerFactory.getInstance("SunX509");  
        kf.init(ks, SERVER_KEY_STORE_PASSWORD.toCharArray());  
          
        context.init(kf.getKeyManagers(), null, null);  
  
        ServerSocketFactory factory = context.getServerSocketFactory();  
        ServerSocket _socket = factory.createServerSocket(8443);
        ((SSLServerSocket) _socket).setNeedClientAuth(true);  

        String mode;
        Scanner scan = new Scanner(System.in);
        while (true) {
            System.out.println("\nPlease select the mdoe, 1 for transcation, 2 for exit.");
            mode = scan.next();
            if (mode.equals("1")) {
                transcation(_socket);
            }else if(mode.equals("2")){
                System.out.println("Exit Successfully. Goob Bye!");
                break;
            }else {
                System.out.print("Wrong Input, please input again");
            }
        }
        scan.close();

    }  
}  
