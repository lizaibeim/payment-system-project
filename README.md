# payment-system-project
Class project for COMP3334 Computer System Security

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

