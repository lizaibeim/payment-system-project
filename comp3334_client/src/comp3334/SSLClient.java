package comp3334;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Map;
import java.util.Scanner;

public class SSLClient {  
    private static String CLIENT_KEY_STORE = "/Library/Java/JavaVirtualMachines/jdk1.8.0_101.jdk/Contents/Home/bin/client_ks";
    private static String CLIENT_KEY_STORE_PASSWORD = "456456";
    private static String publicKey_server;
    private static String publicKey_client;
    private static String privateKey_client;
    private static SHA sha;

      
    public static void main(String[] args) throws Exception {
        String mode;
        Scanner scan = new Scanner(System.in);
        while (true) {
            System.out.println("\nPlease select the mdoe, 1 for transcation, 2 for exit.");
            mode = scan.next();
            if (mode.equals("1")) {
                transcation();
            }else if(mode.equals("2")){
                System.out.println("Exit Successfully. Goob Bye!");
                break;
            }else {
                System.out.print("Wrong Input, please input again");
            }
        }
        scan.close();

    }

    private static void transcation()throws Exception{
        sha = new SHA();
        Map<String, String> keyMap = RSA.createKeys(512);
        publicKey_client = keyMap.get("publicKey");
        privateKey_client = keyMap.get("privateKey");

        //System.out.println("Public key for client: \n\r" + publicKey_client);
        //System.out.println("Private key for client: \n\r" + privateKey_client);


        // Set the key store to use for validating the server cert.
        System.setProperty("javax.net.ssl.trustStore", CLIENT_KEY_STORE);
        //System.setProperty("javax.net.debug", "ssl,handshake");
        SSLClient client = new SSLClient();
        Socket s = client.clientWithCert();

        PrintWriter writer = new PrintWriter(s.getOutputStream());
        BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream()));
        //get server's public key, assume it as secure
        publicKey_server = reader.readLine();
        //System.out.print("Public key for server:\n "+publicKey_server+"\n");

        //transfer the public Key of client to server, assume it as secure
        writer.println(publicKey_client);
        writer.flush();

        //Get the first message from server, and check its integrity
        String[] first;
        while (true) {
            //Get the first message from server, which is the transcation amount
            String cipher_aount = reader.readLine();
            first = dataDecrypt(cipher_aount);
            if(first[1].equals("true")){
                //System.out.println("The content is secure:" + first[0].substring(4));
                //the data integrity is guaranteed
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

        System.out.println("\nThe transcation amount is: "+first[0].substring(4));

        Scanner scan = new Scanner(System.in);
        System.out.print("Input transaction password?");
        String str1;
        str1 = scan.next();
        System.out.println("The transaction password is : " + str1);


        writer.println(dataEncrypt(str1,sha));
        writer.flush();

        //wait for the first response from server, whether the password is transferred correctly or not
        while(true) {
            String response = reader.readLine();
            String[] plaintext = dataDecrypt(response);
            if(plaintext[0].substring(4).equals("true") && plaintext[1].equals("true")){
                System.out.println("Transcation Done.");
                break;
            } else if(plaintext[0].substring(4).equals("wrong") && plaintext[1].equals("true")){
                //indicate that the password is incorrect
                System.out.println("Wrong password, Please enetr your password again:");
                str1 = scan.next();
                writer.println(dataEncrypt(str1,sha));
                writer.flush();
            }
            else { //retransfer the password agian
                writer.println(dataEncrypt(str1,sha));
                writer.flush();
            }
        }
        s.close();
    }


    //get the decrypted message and check its integrity
    private static String[] dataDecrypt(String ciphertext) throws Exception{
        //System.out.println("\n======================Start Decryption======================");
        //decrypt the message first by RSA, then do hash for content to check data integrity
        String digested = RSA.privateDecrypt(ciphertext,RSA.getPrivateKey(privateKey_client));
        //System.out.println("Digested data decrytped from RSA512: [ " + digested + " ]");

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
        String ciphertext = RSA.publicEncrypt(digested,RSA.getPublicKey(publicKey_server));
        //System.out.println("Hashed Data encrypted with RSA 1024: [ " + ciphertext + " ]");

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

    private Socket clientWithoutCert() throws Exception {  
        SocketFactory sf = SSLSocketFactory.getDefault();  
        Socket s = sf.createSocket("localhost", 8443);
        return s;  
    }  
  
    private Socket clientWithCert() throws Exception {  
        SSLContext context = SSLContext.getInstance("TLS");  
        KeyStore ks = KeyStore.getInstance("jceks");  
          
        ks.load(new FileInputStream(CLIENT_KEY_STORE), null);  
        KeyManagerFactory kf = KeyManagerFactory.getInstance("SunX509");  
        kf.init(ks, CLIENT_KEY_STORE_PASSWORD.toCharArray());  
        context.init(kf.getKeyManagers(), null, null);  
          
        SocketFactory factory = context.getSocketFactory();  
        Socket s = factory.createSocket("localhost", 8443);
        return s;  
    }  
}