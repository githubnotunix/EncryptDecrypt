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
//AES
public class Program3
{
    public static void main(String[] args) throws Exception
    {
    	//make key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();

        //make initialization vector
        byte[] IV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
        
        //encryption takes place (where Alice is)
        System.out.println("Original Mesage: ");
		Scanner originalString = new Scanner(System.in);
		String m = originalString.nextLine();
		FileWriter fWriter = null;
		BufferedWriter writer = null;
		
		//counts the average number of encryptions
		long startTime = System.nanoTime();
		for (int i = 0; i < 100; i ++)
		{
		byte [] cipherText = encrypt(m.getBytes(), key, IV);
		String ciphetext = Base64.getEncoder().encodeToString(cipherText);
		try {
			fWriter = new FileWriter("ctext.txt");
			writer = new BufferedWriter(fWriter);
			writer.write(ciphetext);
			writer.newLine();
			writer.close();
			//System.out.println("counting");
			//System.out.println("file was created/saved");
		}
		catch(Exception e)
		{
			System.out.println("fix the error");
		}
		}	
		long stopTime = System.nanoTime();
		long elapsedTime = stopTime - startTime;
		long average = elapsedTime/100;
		System.out.print("\nAverage Time For One Encryption: " + average + " nanoseconds" + "\n");
		
		//counts the decryptions
		long start = System.nanoTime();
		for(int j = 0; j < 100; j++)
		{
		FileReader fr = new FileReader("ctext.txt");
		BufferedReader br = new BufferedReader(fr);
		String str;
		try {
    		while((str = br.readLine()) != null)//didn't want 100 print out statements
    		{
    			//System.out.println("\nEncrypted Message: ");
    			//System.out.println(str);
    			byte[] decryptedText = Base64.getDecoder().decode(str);
    			//System.out.println(decryptedText);
    			String t = decrypt(decryptedText, key, IV) ;
    			//System.out.println("\nDecrypted Message: ");
    			//System.out.println(t);
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
		System.out.print("Average Time For One Decryption: " + average_decrypt + " nanoseconds");
}
    
    public static byte[] encrypt (byte[] plaintext,SecretKey key,byte[] IV ) throws Exception
    {
    	//System.out.println("ENCRYPT");
        //initialize and allocate
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        //encrypt
        byte[] cipherText = cipher.doFinal(plaintext);
        
        return cipherText;
    }
    
    public static String decrypt (byte[] cipherText, SecretKey key,byte[] IV) throws Exception
    {
    	//System.out.println("DECRYPT");
    	//initialize and allocate
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        
        //decryt
        byte[] decryptedText = cipher.doFinal(cipherText);
        
        return new String(decryptedText);
    }
}