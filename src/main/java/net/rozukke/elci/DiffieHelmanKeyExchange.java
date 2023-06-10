package net.rozukke.elci;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import at.favre.lib.hkdf.HKDF;

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

    public byte[] getServerPublicKeyData(){
        return this.serverPublicKeyData;
    }

    public KeyPair getServerKeyPair(){
        return this.serverKeyPair;
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
        if (sharedSecretData.length==256) {
            return true;
        } 
        // Returns false is shared secret is not correct length (may be due to tampering etc)
        return false;
    }  catch (Exception e) {
         System.out.println(e.toString());
         return false;
    }
        
    }



    // private static String bytesToHex(byte[] bytes) {
    //     StringBuilder result = new StringBuilder();
    //     for (byte b : bytes) {
    //         result.append(String.format("%02X", b));
    //     }
    //     return result.toString();
    // }

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
            System.out.println(e.toString());
            return false;
        }
    }
    // Reference https://www.baeldung.com/java-hmac
    public byte[] verifyHMAC(byte[] messageDecoded) throws Exception {
        if (KeyExhangeSuccessful==true) {
            try {

                byte[] bytesReceivedHMAC = Arrays.copyOfRange(messageDecoded, 0, 32);
                byte[] bytesReadContent = Arrays.copyOfRange(messageDecoded,32,messageDecoded.length);


              

                SecretKeySpec authKeySpec = new SecretKeySpec(authenthicationKey.getEncoded(),authenthicationKey.getAlgorithm());
                Mac hmac = Mac.getInstance("HmacSHA256");
                hmac.init(authKeySpec);
                byte[] bytesCalculatedHMAC=hmac.doFinal(bytesReadContent);
                

                if (Arrays.equals(bytesReceivedHMAC,bytesCalculatedHMAC)) {
                    return bytesReadContent;
                } else{
                     throw new Exception("MAC Verification Failed!");
                }

            } catch (Exception e) {
                throw new Exception(e);
            }


        }
        
        return null;
    }



    public String doDecryption(byte[] bytesContentEncrypted) {
        if (KeyExhangeSuccessful==true){
            try{
                byte[] EncryptedContentBytes = Arrays.copyOfRange(bytesContentEncrypted, 16, bytesContentEncrypted.length);
                byte[] ivBytes = Arrays.copyOfRange(bytesContentEncrypted, 0, 16);
                
                
                IvParameterSpec ivParameters = new IvParameterSpec(ivBytes);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

                cipher.init(Cipher.DECRYPT_MODE,this.encryptionKey,ivParameters);

                byte[] decrypted_content = cipher.doFinal(EncryptedContentBytes);
                String decrypted_plaintext= new String(decrypted_content);
                
                return decrypted_plaintext;
    
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }



        return "FAILED TO DECRYPT";
    }
    

    
    
    
}
