import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
//AES CBC
public class Program1
{
    
    public static void main(String[] args) throws Exception
    {
    	//make key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey k = keyGenerator.generateKey();//shared secret key 
        
        //make initialization vector
        byte[] IV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
        
        //scans original message
        System.out.println("Original Mesage: ");
		Scanner originalString = new Scanner(System.in);
		String m = originalString.nextLine();
		
		//initialize file stuff
		FileWriter fWriter = null;
		BufferedWriter writer = null;
		
		//actual encryption is done (where Alice is implemented)
		byte [] cipherText = encrypt(m.getBytes(), k, IV);
		String ciphetext = Base64.getEncoder().encodeToString(cipherText);//bytes to string
		try {
			//writes encrypted message into file
			fWriter = new FileWriter("ctext.txt");
			writer = new BufferedWriter(fWriter);
			writer.write(ciphetext);
			writer.newLine();
			writer.close();
			//System.out.println("file successfully created");
		}
		catch(Exception e)
		{
			System.out.println("fix the error");
		}
		
		//read the ecrypted text to decrypt it (where Bob is implemented)
		FileReader fr = new FileReader("ctext.txt");
		BufferedReader br = new BufferedReader(fr);
		String str;
		try {
    		while((str = br.readLine()) != null)
    		{
    			System.out.println("\nAlice's Encrypted Message: ");
    			System.out.println(str);
    			byte[] decryptedText = Base64.getDecoder().decode(str);
    			//System.out.println(decryptedText);
    			String m2 = decrypt(decryptedText, k, IV) ;
    			System.out.println("\nBob's Decrypted Message: ");
    			System.out.println(m2);//back to original message
    		}
    		br.close();
    		}
    		catch (Exception e) {
    			System.out.println("File not found");
    		}
    }
    
    public static byte[] encrypt (byte[] plaintext,SecretKey key,byte[] IV ) throws Exception
    {
    	//gets all necessary parameters and intitializes cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        //performs the encryption
        byte[] cipherText = cipher.doFinal(plaintext);
        
        return cipherText;
    }
    
    public static String decrypt (byte[] cipherText, SecretKey key,byte[] IV) throws Exception
    {
    	//gets all necessary parameters and intitializes cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        
        //performs the decryption
        byte[] decryptedText = cipher.doFinal(cipherText);
        
        return new String(decryptedText);
    }
}