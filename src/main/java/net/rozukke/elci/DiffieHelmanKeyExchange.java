package net.rozukke.elci;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
// import java.net.ServerSocket;
// import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
// import java.io.*;
import at.favre.lib.hkdf.HKDF;
// import static java.nio.charset.StandardCharsets.UTF_8;
public class DiffieHelmanKeyExchange {
    
    //  Reference 
    // https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
    // https://github.com/patrickfav/hkdf

    private KeyPair serverKeyPair;
    private PublicKey clientPublicKey;
    private byte[] serverPublicKeyData;
    private byte[] sharedSecretData;    
    private SecretKey encryptionKey;
    private SecretKey authenthicationKey;
    private boolean KeyExhangeSuccessful;
   
    // Information Provided to HKDF for key derivation
    final String ENCRYPTION_SALT="encrypt_salt";
    final String ENCRYPTION_INFORMATION="encryption_info";
    final String AUTHENTICATION_SALT="auth_salt";
    final String AUTHENTHICATION_INFORMATION="authentication_info";
    
    //Getters

    public String getServerPublicKeyDataBase64Encoded(){
        String base64Encoded = Base64.getEncoder().encodeToString(this.serverPublicKeyData);
        return base64Encoded;
    }

    public KeyPair getServerKeyPair(){
        return this.serverKeyPair;
    }

    public String getSharedSecretData(){
        return  String.valueOf(this.sharedSecretData.length);
    }



    public DiffieHelmanKeyExchange() throws Exception {
        this.serverKeyPair=InitalizeKeyExchange();
        this.serverPublicKeyData=generatePublicKey(serverKeyPair);
        this.clientPublicKey=null;
        this.sharedSecretData=null;
        this.encryptionKey=null;
        this.authenthicationKey=null;
        this.KeyExhangeSuccessful=false;

    }


    public static KeyPair InitalizeKeyExchange() throws Exception{
        KeyPairGenerator keyPairGenDH = KeyPairGenerator.getInstance("DiffieHellman");
        keyPairGenDH.initialize(2048); // Specify the length of the key ---> AES 256
        KeyPair serverKeyPair = keyPairGenDH.generateKeyPair();
        return serverKeyPair;
    }

    public static byte[] generatePublicKey(KeyPair serverKeyPair) {
        byte[] serverPublicKeyBytes = serverKeyPair.getPublic().getEncoded();
        return serverPublicKeyBytes;
    }

    //Deseralize the recevied client public key
    public PublicKey convertClientPublciKey(byte[] clientPublicKeySerialized) throws Exception{
        // Convert the public key froms bytes into KeySpec then into the public key
        KeyFactory keyFac = KeyFactory.getInstance("DiffieHellman");
        X509EncodedKeySpec keySpec= new X509EncodedKeySpec(clientPublicKeySerialized);
        this.clientPublicKey= keyFac.generatePublic(keySpec); // Generate public key from keySpec
        return clientPublicKey;
    }

    public boolean generateSharedSecret(KeyPair serverKeyPair , PublicKey clientPublicKey) {
        
        try{
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
        keyAgreement.init(serverKeyPair.getPrivate()); // Intalize the key agreement
        keyAgreement.doPhase(clientPublicKey, true);  // Do the last phase of the key exchange, parameters are specified in the public key
        this.sharedSecretData = keyAgreement.generateSecret(); // Generate Shared Secret 
        System.out.println(sharedSecretData.length);
        if (sharedSecretData.length==256) {
            return true;
        } 
        // Returns false is shared secret is not correct length (may be due to tampering etc)
        return false;
    }  catch (Exception e) {
        return false;
    }
        
    }



    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    private byte[] getDerivedKeyData(byte[] sharedSecret, String salt , String information){

        byte[] salt_bytes = salt.getBytes(StandardCharsets.UTF_8);
        HKDF derivation_function = HKDF.fromHmacSha256();
            
        byte[] derived_material=derivation_function.extract(salt_bytes,sharedSecret);

        byte[] derived_key=derivation_function.expand(derived_material,information.getBytes(StandardCharsets.UTF_8),32);

        return derived_key;

    }

    private void setAuthenthicationKey (byte[] authenthicationKeyData) {
       this.authenthicationKey = new SecretKeySpec(authenthicationKeyData,"AES");
    }

    private void setEncryptionKey(byte[] encryptionKeyData) {
        this.encryptionKey= new SecretKeySpec(encryptionKeyData, "AES");
    }

    // Perform key Derivation and convert to SecretKey format 
    public boolean finalizeKeyExchange() {

        try{

        byte [] derived_encryption_key=getDerivedKeyData(this.sharedSecretData, ENCRYPTION_SALT,ENCRYPTION_INFORMATION);
        byte [] derived_authentication_key=getDerivedKeyData(this.sharedSecretData, AUTHENTICATION_SALT,AUTHENTHICATION_INFORMATION);
        
        setEncryptionKey(derived_encryption_key);
        setAuthenthicationKey(derived_authentication_key);
        
        this.KeyExhangeSuccessful=true;
        return true;

        } catch (Exception e) {
            return false;
        }
    }


    public String doDecryption(String contentEncrypted) {
        if (KeyExhangeSuccessful==true){
            try{
                byte[] bytesRead = Base64.getDecoder().decode(contentEncrypted);
                byte[] EncryptedContentBytes = Arrays.copyOfRange(bytesRead, 16, bytesRead.length);
                byte[] ivBytes = Arrays.copyOfRange(bytesRead, 0, 16);
               
                IvParameterSpec ivParameters = new IvParameterSpec(ivBytes);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE,this.encryptionKey,ivParameters);
                byte[] decrypted_content = cipher.doFinal(EncryptedContentBytes);
                String decrypted_plaintext= new String(decrypted_content);
                
                return decrypted_plaintext;
    
        } catch (Exception e) {
            return null;
        }
    }



        return "bruh";
    }
    

    // public static boolean createHMAC(SecretKey authenticationKey, byte[] received_content)


    // public static void main(String[] args) throws Exception{
        
    //     // BufferedReader in;
    //     // BufferedWriter out;

        
    //     // // Start the server
    //     // int serverPort = 4711;
    //     // ServerSocket serverSocket = new ServerSocket(serverPort);
    //     // System.out.println("Server started. Listening on port " + serverPort + "...");

    //     // // Accept client connection
    //     // Socket clientSocket = serverSocket.accept();
    //     // System.out.println("Client connected.");

    //     // out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream(), StandardCharsets.UTF_8));

    //     // in = new   BufferedReader(new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8));
       

    //     // DiffieHelmanKeyExchange DH = new DiffieHelmanKeyExchange();
    //     // // System.out.println(DH.getServerPublicKeyDataBase64Encoded());
    //     // out.write(DH.getServerPublicKeyDataBase64Encoded());
    //     // out.flush();


    //     // String ReceivedLine = in.readLine();


    //     // // if (ReceivedLine!=null) {
    //     // //     byte[] bytesRead = Base64.getDecoder().decode(ReceivedLine);
    //     //     PublicKey ClientPublicKey =DH.convertClientPublciKey(bytesRead);
    //     //     System.out.println(DH.getSharedSecretData());
    //     //     DH.generateSharedSecret(DH.serverKeyPair, ClientPublicKey);
    //     //     System.out.println(bytesToHex(DH.getSharedSecretData()));
           
    //     // }


        
        
    //     // // 
    //     // byte [] derived_encryption_key=getDerivedKey(sharedSecret, "encrypt_salt", "encryption_info");

    //     // byte [] derived_authentication_key=getDerivedKey(sharedSecret, "auth_salt", "authentication_info");

    //     // // String encryption_string=bytesToHex(derived_encryption_key);
    //     // // System.out.println(encryption_string);

        
    //     // // String authentication_string=bytesToHex(derived_authentication_key);
    //     // // System.out.println(authentication_string);

    //     // 
    //     //

    //     // clientSocket.close();

    //     // //Accept client connection
    //     // Socket NewSocket = serverSocket.accept();
    //     // System.out.println("Client connected.");

     
        
    //     // // Received Encrypted Data

    //     //   // Receive the client public key from the client
    //     // //   byte[] EncryptedContentBytes = new byte[4096];
      
    //     // //   int bytesRead = inputStream.read(EncryptedContentBytes);
    //     // //   byte[] ivBytes = Arrays.copyOfRange(EncryptedContentBytes, 0, 16);
    //     // //   EncryptedContentBytes = Arrays.copyOfRange(EncryptedContentBytes, 16, bytesRead);
    //     // // //   System.out.println(EncryptedContentBytes.length);
    //     // // //   System.out.println(bytesToHex(EncryptedContentBytes));
    //     // // //   System.out.println(bytesToHex(ivBytes));

    //     // // EncryptedContentEncoded = inputStream.read
          
    //     // in = new BufferedReader(new InputStreamReader(NewSocket.getInputStream(), StandardCharsets.UTF_8));
    //     // String ReceivedLine = in.readLine();
    //     // System.out.println(ReceivedLine);
    //     // if (ReceivedLine!=null){
    //     //         byte[] bytesRead = Base64.getDecoder().decode(ReceivedLine);
    //     //         byte[] EncryptedContentBytes = Arrays.copyOfRange(bytesRead, 16, bytesRead.length);
    //     //         byte[] ivBytes = Arrays.copyOfRange(bytesRead, 0, 16);
               
    //     //         IvParameterSpec ivParameters = new IvParameterSpec(ivBytes);

    //     //         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    //     //         cipher.init(Cipher.DECRYPT_MODE,EncryptionKey,ivParameters);
    //     //         byte[] decrypted_content = cipher.doFinal(EncryptedContentBytes);
    //     //         String decrypted_plaintext= new String(decrypted_content);
    //     //         System.out.println(decrypted_plaintext);

    //     // }
        

        
        

    //     // serverSocket.close();
    //     // clientSocket.close();
    //  }
    
}
