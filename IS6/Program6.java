import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
//import org.apache.commons.codec.binary.Base64;
import java.util.Base64;
import java.util.Scanner;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;

import javax.xml.bind.DatatypeConverter;
public class Program6 {
  public static void main(String[] args) {
	//command line stuff
	System.out.println("Original Message: ");
	Scanner originalString = new Scanner(System.in);
	String m = originalString.nextLine();
	FileWriter fWriter = null;
	BufferedWriter writer = null;
	
  
	//main code
	try {
	 //secret key/hmac initialization
		String secret = "secretaladaldneif";
		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
		sha256_HMAC.init(secret_key);

     //reading to the file (where Alice is)
     // System.out.println(hash);
		fWriter = new FileWriter("mactext.txt");
		writer = new BufferedWriter(fWriter);
		writer.write(m);//m is original text
     	writer.newLine();
     	long startTime = System.nanoTime();
     	for(int i = 0; i < 100; i++)
     	{
     	String hash = Base64.getEncoder().encodeToString(sha256_HMAC.doFinal(m.getBytes()));
     	}
     	long stopTime = System.nanoTime();
     	long elapsedTime = stopTime -startTime;
     	long average_sign = elapsedTime/100;
     	System.out.println("Average Time For One HMAC Generation: " + average_sign + " nanoseconds");
	//	writer.write(hash);//actual hash
	//	System.out.println("\nInitial Hash Message: \n" + hash );
		writer.close();
		fWriter.close();
		
  	/*String text = "what"
		System.out.println(Base64.getEncoder().encodeToString(sha256_HMAC.doFinal(text.getBytes())));*/  
		
		//read file (where Bob is)
		FileReader fr = new FileReader("mactext.txt");
		BufferedReader br = new BufferedReader(fr);
		String str;
		while((str = br.readLine()) != null)
		{
	//		System.out.print("\nFinal Message (from file): \n" + str + "\n");
			String new_hash = Base64.getEncoder().encodeToString(sha256_HMAC.doFinal(str.getBytes()));//rehash the message read from file
	//		System.out.println("\nFinal Hash Message: \n" + new_hash);
			br.readLine();//skips to the second line which is the hash messsage
	/*		if(hash.equals(new_hash))
					System.out.println("\nVERIFIED");
			else
				System.out.println("\nNOT VERIFIED");*/ 
		}
		br.close();
		}
		catch (Exception e) {
			System.out.println("File not found");
		}
    
   
  }
  
}