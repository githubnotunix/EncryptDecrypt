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
//RSA 2048
public class Program2 {
	
    public static void main(String[] args) throws Exception {

    	//declare public/private keys
        Map<String, Object> keys = getRSAKeys();
        PrivateKey privateKey = (PrivateKey) keys.get("private");
        PublicKey publicKey = (PublicKey) keys.get("public");

        //input to command line
        System.out.println("Original Message: ");
		Scanner originalString = new Scanner(System.in);
		String m = originalString.nextLine();
		
		//encryption takes place (Alice is implemented)
		FileWriter fWriter = null;
		BufferedWriter writer = null;
        String encryptedText = encryptMessage(m, privateKey);//actual encryption
        try {
			fWriter = new FileWriter("ctext.txt");
			writer = new BufferedWriter(fWriter);
			writer.write(encryptedText);
			System.out.println("\nAlice's Encrypted Text: ");
			writer.newLine();
			writer.close();
			fWriter.close();
			//System.out.println("file was successfully created");
		}
		catch(Exception e)
		{
			System.out.println("fix the error");
		}

        //decryption takes place (Bob is implemented)
        try {
			FileReader fr = new FileReader("ctext.txt");
			BufferedReader br = new BufferedReader(fr);
			String str;
				while((str = br.readLine()) != null)
				{
					System.out.println(str);
					String decryptedText = decryptMessage(str, publicKey) ;//actual decryption
					System.out.println("\nBob's Decrypted Text: ");
					System.out.println(decryptedText);//back to original message
				}
			br.close();
			}
			catch (Exception e) {
				System.out.println("File not found");
			}	
    }
 
    //makes the keys
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

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);//uses PUBLIC key
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }
    private static String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);//uses PRIVATE key
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

 

}