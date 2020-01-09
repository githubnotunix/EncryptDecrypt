import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.KeyPair;
import java.io.BufferedReader;
import java.io.FileReader;
import java.security.KeyPairGenerator;

import java.security.PrivateKey;

import java.security.PublicKey;

import java.util.Base64;

import java.util.HashMap;

import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;

public class Program3_2 {

    public static void main(String[] args) throws Exception {

    	//makes keys
        Map<String, Object> keys = getRSAKeys();
        PrivateKey privateKey = (PrivateKey) keys.get("private");
        PublicKey publicKey = (PublicKey) keys.get("public");

        //input to command line
        System.out.println("Original Message: ");
		Scanner originalString = new Scanner(System.in);
		String i = originalString.nextLine();
		FileWriter fWriter = null;
		BufferedWriter writer = null;
		
		//calculates average encryption
		long startTime = System.nanoTime();
		for(int j = 0; j < 100; j++)
		{
        String encryptedText = encryptMessage(i, privateKey);
        try {
			fWriter = new FileWriter("ctext1.txt");
			writer = new BufferedWriter(fWriter);
			writer.write(encryptedText);
			//System.out.println(encryptedText);
			writer.newLine();
			writer.close();
			fWriter.close();
			//System.out.println("file was created/saved");
		}
		catch(Exception e)
		{
			System.out.println("fix the error");
		}
		}
		
		//caluculates time for average decryption
		long stopTime = System.nanoTime();
		long elapsedTime = stopTime - startTime;
		long average_encrypt = elapsedTime/100;
		System.out.print("Average Time for Encryption: " + average_encrypt + " nanoseconds \n");
		long start = System.nanoTime();
		for(int k = 0; k < 100; k++)
		{
        try {
			FileReader fr = new FileReader("ctext1.txt");
			BufferedReader br = new BufferedReader(fr);
			String str;
			
			while((str = br.readLine()) != null)
			{
				//System.out.println(str);
				String decryptedText = decryptMessage(str, publicKey) ;
				//System.out.println(decryptedText);
			}
			br.close();
			}
			catch (Exception e) {
				System.out.println("File not found");
			}
		}
		long stop = System.nanoTime();
		long elapsed = stop - start;
		long average_decrypt = elapsed/100;
		System.out.println("Average Time For One Decryption: " + average_decrypt + " nanoseconds");
    }

    private static Map<String,Object> getRSAKeys() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        Map<String, Object> keys = new HashMap<String,Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }
    private static String decryptMessage(String encryptedText, PublicKey publicKey) throws Exception {
    	//System.out.println("DECRYPT");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);//uses PUBLIC key
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }
    
    private static String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {
    	//System.out.println("ENCRYPT");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);//uses PRIVATE key
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

 

}