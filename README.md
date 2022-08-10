# secure-payment-system

## Program structure
	Client side:
		Class:
                	SSLClient: Build up a socket listening on port 8443. 
          	Methods: 
                	transaction (): view a transaction sent from server, input password to permit; 
                	dataDecryption (): decrypt data; 
                	dataEncryption (): encrypt data; 
                	strToSeconds (): convert time from minutes: seconds form to seconds; clientWithCert (): complete certification of client to server
  	Server side:
		Class:
			SSLServer: Build up a socket listening on port 8443. 
          	Methods:
                	transaction (): launch a transaction by sending transaction amount to client and verify the password sent from client; 
                	dataDecryption (): decrypt data; 
                	dataEncryption (): encrypt data; 
                	strToSeconds (): convert time from minutes: seconds form to seconds
  	On both side:
		Class:
                	RSA: RSA class, including some methods to implement. 
                	SHA: SHA class, including method to hash by SHA1 algorithm. 

          	Methods:
                	getPrivateKey (): get the RSA private key;
                	publicEncrypt (): encrypt with RSA public key
                	privateDecrypt (): decrypt with RSA private key
                	rsaSplitcode (): for large data set to be encrypted by RSA, split it into proper size
                	sha1(): hash data by SHA1 algorithm

## Security mechanism
### ●	SSL Record Protocol and SSL Handshake Protocol
SSL Record Protocol is based on the secure transaction protocol (e.g., TCP), providing basic services like data encapsulation, compression, and encryption. SSL Handshake Protocol is based on the SSL Record Protocol, used before the data transaction, providing services like identity authentication, encryption algorithms negotiation, and key exchange. 

What services provided by SSL are 
1.	Authenticate users and servers to ensure that data is sent to the correct client and server;
2.	Encrypt data to prevent data from being stolen in the middle;
3.	Maintain data integrity and ensure that data is not changed during transmission.

In our online payment system implementation, we first use Java keytool to generate certificates of client and server. Then, we export them out and import them into the other’s key store. Corresponding commands are shown in the section: Application installation guide -- Prepare certificates. The certificates are used for later RSA encryption algorithms

Then we use Java SSL package (javax.net.ssl) to implement the authentication of client and server.
![image](https://user-images.githubusercontent.com/38242437/183751812-b24bd14d-c350-4006-86e6-15e8a27ec6da.png)

1.	The client sends ClientHello message to the server. The message includes supported encryption algorithms and so on.
![image](https://user-images.githubusercontent.com/38242437/183752343-3ad607b2-7610-49d7-9178-47d4bd185439.png)

2.	The server responds with ServerHello message and notifies one of the encryption methods (RSA in our system) chosen from the encryption algorithms that the client supports to the client.
![image](https://user-images.githubusercontent.com/38242437/183752793-45403ff6-f065-4263-83c7-7cad38abd9a0.png)
![image](https://user-images.githubusercontent.com/38242437/183752821-3ad7e46b-6271-46a2-aaf5-7c92469ba620.png)

3.	With this encryption algorithm, the server sends its public key to the client.
![image](https://user-images.githubusercontent.com/38242437/183753051-fbf24acc-093e-4ba9-83eb-ca22fa72f497.png)

4.	The negotiation between the server and the client is done. The server sends ServerHelloDone message to the client.
![image](https://user-images.githubusercontent.com/38242437/183753129-1cf4b63a-29c5-42c7-a7b4-64787cec51ca.png)
![image](https://user-images.githubusercontent.com/38242437/183753150-0a980a71-d6e5-45ac-8fc5-06a79d14fda1.png)
![image](https://user-images.githubusercontent.com/38242437/183753170-8690c383-0c64-4ef6-a9a7-517ca8336629.png)

5.	The client uses the server’s public key to create a session key and send to the server using ECDHClientKeyExchange message.
![image](https://user-images.githubusercontent.com/38242437/183753846-c230b221-8ffb-4061-b4f0-11dbf3168dda.png)

6.	The client notifies the server to change the encryption algorithm and sends with Change Cipher Spec message. 
![image](https://user-images.githubusercontent.com/38242437/183753904-914411b4-f4ab-419e-93a2-2761ebe8e784.png)

7.	The client sends the Finished message to inform the server to check the request of changing the encryption algorithm.
![image](https://user-images.githubusercontent.com/38242437/183753946-956fe999-12e2-4bc3-b26a-a1487fdbcdb5.png)

8.	The server ensures that the algorithm has been changed and returns Change Cipher Spec message.
![image](https://user-images.githubusercontent.com/38242437/183753975-fa4e7349-e88d-4d44-ae33-e911b0bdf456.png)

9.	The server sends the Finished message.
![image](https://user-images.githubusercontent.com/38242437/183754015-10a41a97-57f1-4471-93e1-31b4b1b7be68.png)

10.	After authentication of the client and the server, the communication begins and the communication data are in protection. 
![image](https://user-images.githubusercontent.com/38242437/183754139-88f698d7-e883-4f11-a464-f258022061cf.png)
![image](https://user-images.githubusercontent.com/38242437/183754183-dc3cd7b6-3722-42c8-9b29-9dec1091e978.png)

The generated session key is used to encrypt data during communication between the client and the server. However, the session key is the symmetric key, so if the data is intercepted by others, it may be decrypted by malicious individuals due to lower security compared to the asymmetric key.  This problem will be solved with the following security mechanism.

### ●	Encryption-with-Password Authentication Protocol
After construct the SSL authentication protocol, the server and client can trust each other under the premise that the communication between them are secure.

For basic communication between server and client, it is encrypted first via AES with the session key. Besides the basic communication encryption, this program adopts RSA algorithm and SHA1 algorithm to encrypt the data. 

#### SHA1 (with timestamp)
Firstly, the data to be sent would be concatenated with the current timestamp accessed from the system time. The concatenated data then is hashed by the SHA1 algorithm, and it will produce digested information. 
For the same data, because of the different timestamps, their digested information also is different. This algorithm can be used to verify the data integrity to prevent it from malicious tampering.

#### RSA 512/1024
Then, after the concatenated data is digested, the digested information plus the raw concatenated data is encapsulated into a single String. The String is encrypted by RSA 512/1024 algorithm, and it will produce a cipher text of the String. This procedure can prevent unauthorized users from viewing plaintext information. Because RSA is encrypted by asymmetric key pairs, it is difficult to decrypt by brute force without keys.

Before the secure communication, the server and client need to transfer their public key of RSA to the other. The key pairs are generated by KeyPairGenerator specified with a certain algorithm (RSA).

For the server side, it stores the private key and public key of itself and the public key of the client.
![image](https://user-images.githubusercontent.com/38242437/183756751-c1ff5644-d5a5-4755-b79a-2a3e595b2ca3.png)

For the client side, it stores the private key and public key of itself and the public key of the server. 
![image](https://user-images.githubusercontent.com/38242437/183756821-4337a448-1a16-496a-95da-210635c6dae3.png)

When the server sends a message to the client, the server will concatenate the message with the timestamp. In the snapshot (Digest Data -> Content), the first four digits such as 0779 are the total seconds to represent the *minutes:seconds* form, and 500 is the message to be sent.
Then use the SHA1 function to generate digested information. Create a new String consisting of the digested information and the concatenated message (with timestamp). In the snapshot, it is represented by the Digested Data (Hashvalue and Content).
At last, use the RSA512 algorithm to encrypt the new String by the client’s public key. The result is shown by Hash Data encrypted with RSA 512. 
![image](https://user-images.githubusercontent.com/38242437/183757179-b5fedb46-63f3-47ae-a8ae-cb12aa1de06c.png)

On the client side, the client receives the cipher text and decrypts the cipher text with its private key. 
![image](https://user-images.githubusercontent.com/38242437/183757214-d83a0406-adef-4ea8-b3d6-94fa203bacdf.png)

When the client gets the new String, it would use the concatenated message to generate new digested information by the SHA1 algorithm. Then, it will compare the new digested information with the digested information part in the new String. If the two are equal, the data is with integrity and the client will send a response to inform the server of the successful transmission with the message “true”. Otherwise, the data have been tampered and the client will request the server to resend the message with “false”. The response and request messages are encrypted too. 
![image](https://user-images.githubusercontent.com/38242437/183759752-0ef80390-e445-4a07-bc27-c841531e39c7.png)

#### Password authentication
The client needs to input their password to complete the transaction. 
![image](https://user-images.githubusercontent.com/38242437/183759969-9b8165de-d8f3-4c82-aa84-d360aa5007f1.png)

If the password is transferred appropriately, the server will check the password whether is correct or not by comparing the received password with the pre-stored password related to the client (In our program, the client is Alice, and the password is 12345). 
![image](https://user-images.githubusercontent.com/38242437/183760643-68ca9359-3742-4343-94b7-89a41c9e3391.png)

If the password doesn’t match, the server will inform the client of inputting the incorrect password with the message “wrong”. 
![image](https://user-images.githubusercontent.com/38242437/183760673-2a57fa0b-5428-4c56-924f-df13aa3cc5c5.png)

Then, the client will prompt the user to re-enter the password again.
![image](https://user-images.githubusercontent.com/38242437/183760719-5af9896b-982c-4a3c-9b6f-a861cb247e69.png)

#### Random Session Key and Random RSA key pair
For different sessions (based on SSL record protocol and SSL handshake protocol), the session keys shared by the client and server are different. In the same session, for each transaction, the RSA key pairs of client and server are also different.  The difference is shown as follow in two transactions:

![image](https://user-images.githubusercontent.com/38242437/183761446-651bad1b-45eb-4058-b05c-d028dd348bde.png)
![image](https://user-images.githubusercontent.com/38242437/183761463-58c9b8f3-3130-485d-8b37-f50693cfde1c.png)

This kind of mechanism can prevent attackers from sending permit packets intercepted from previous “client-server communication” to the server to conduct a fake transaction. The previous permit packet encrypted from an obsolete client private key could not be decrypted by the server with a new public key of the client, so the transaction would fail.

## Application installation guide
Firstly, the user should go to the directory which stores the java keytool to generate digital certificates for the client and server. Under the java environment, the digital certificate is generated by keytool, which is stored in the concept of the “store”, referring to the certificate warehouse. Call the keytool command to generate a digital certificate for the server and save the certificate store it uses.
![image](https://user-images.githubusercontent.com/38242437/183762112-41259d04-5cba-46ff-8a00-55f9d0f10585.png)

Do the same command for generating the client’s digital certificate.
![image](https://user-images.githubusercontent.com/38242437/183762156-c0b2206a-c208-4ab9-926b-39cc82575b87.png)

Since the certificate of the server is generated manually and there is no signature of any trusted organization, the client cannot verify the validity of the server certificate, and the communication will inevitably fail. It needs to create a repository for the client that holds all the credentials, and then import the server certificate into the repository. In this way, when the client connects to the server, it will find that the server's certificate is in its own trust list, and it can communicate normally.

Next, export the certificate of the server and import it into the client's repository. The first step is to export the certificate of the server  
The password is: server
![image](https://user-images.githubusercontent.com/38242437/183762428-90543521-ea34-441b-b288-9e1bfcdbdd62.png)
Then import the exported certificate into the client certificate store    
The password is: client
![image](https://user-images.githubusercontent.com/38242437/183762546-bab43db9-6ba1-441b-be94-ac50c51f2166.png)

Do the same command for the client  
The password is: client
![image](https://user-images.githubusercontent.com/38242437/183762710-72685f0f-6eca-4788-afc3-c116f27da8c6.png)
The password is: server
![image](https://user-images.githubusercontent.com/38242437/183762728-1bad824f-a37a-4d95-98b4-c109510eb33c.png)

## Use cases (3)
#### 1.
Please ensure that port 8843 is unused before running the program. The jar files are in path *comp3334_client/out/artifacts/comp3334_client_jar* and *comp3334_server/out/artifacts/comp3334_server_jar*.  
Firstly, do the command `java –jar comp3334_server.jar in terminal 1`  
Open another terminal 2, do the command `java –jar comp3334_client.jar`
![image](https://user-images.githubusercontent.com/38242437/183764068-6eba5dd7-48ab-4e51-93cf-e5dbde532faf.png)
![image](https://user-images.githubusercontent.com/38242437/183764118-4334285b-2fb1-47e7-97df-0743b005534e.png)  
Select the mode, 1 for transaction, 2 for exit.

The transaction is launched by the server. Input the amount to be verified by the client.
![image](https://user-images.githubusercontent.com/38242437/183764275-5c9ff5f8-f335-488c-a246-9f396352faeb.png)  

On client side, the client receives the amount from the server, user input the password to permit.
![image](https://user-images.githubusercontent.com/38242437/183764424-717640b4-27ed-4d5d-b8eb-2c2fa64e7ad3.png)  

If the user inputs an incorrect password, then the server would inform the client and the client will prompt the user.
![image](https://user-images.githubusercontent.com/38242437/183765573-5c7cf75c-90ef-4a00-ac1c-9138c4c78184.png)

If the user inputs correct password, then transaction is done.
![image](https://user-images.githubusercontent.com/38242437/183766149-a1f8a650-50d1-4528-ab44-cb29c8578568.png)
![image](https://user-images.githubusercontent.com/38242437/183766256-21f60865-b6d8-4c10-bf9f-a15f356ad78a.png)

#### 2.
![image](https://user-images.githubusercontent.com/38242437/183766494-07f7e43d-db9e-42b1-a7bd-9e141ccf6a3f.png)
![image](https://user-images.githubusercontent.com/38242437/183766502-e9c51e48-d0b9-481a-aeaa-c78b8b91deab.png)

#### 3.
![image](https://user-images.githubusercontent.com/38242437/183766524-44c1da32-a344-4d43-bb54-fa9da72a1977.png)
![image](https://user-images.githubusercontent.com/38242437/183766533-eb6756a2-de02-4bf9-8389-5bec1b4d0452.png)

Input 2 in both terminal to close the session
![image](https://user-images.githubusercontent.com/38242437/183766570-8180380c-8f39-45ce-82e8-dbf0c908fd51.png)
![image](https://user-images.githubusercontent.com/38242437/183766582-af1d650d-da9b-4ee7-ab5d-b81bd62723f4.png)

## Authors  
[**YiFan Jiang**](https://www.linkedin.com/in/yifan-jiang-0828/)  
[**Zaibei Li**](https://www.linkedin.com/in/zaibei-eric-li/)
