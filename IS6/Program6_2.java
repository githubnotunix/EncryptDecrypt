import javax.crypto.Cipher;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

import static java.nio.charset.StandardCharsets.UTF_8;
//RSA
public class Program6_2 {
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }
    public static KeyPair getKeyPairFromKeyStore() throws Exception {
        InputStream ins = Program6.class.getResourceAsStream("/keystore.jks");

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, "s3cr3t".toCharArray());
        KeyStore.PasswordProtection keyPassword =     
                new KeyStore.PasswordProtection("s3cr3t".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate("mykey");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    public static void main(String... argv) throws Exception {
        //get keys
        KeyPair pair = generateKeyPair();
        //KeyPair pair = getKeyPairFromKeyStore();
        
        //encryption happens (where Alice is)
        System.out.println("Type your message: ");
		Scanner originalString = new Scanner(System.in);
		String m = originalString.nextLine();
		FileWriter fWriter = null;
		BufferedWriter writer = null;
		String cipherText = encrypt(m, pair.getPublic());
        try {
			fWriter = new FileWriter("sigtext.txt");
			writer = new BufferedWriter(fWriter);
			writer.write(m);
			writer.newLine();
			//writer.close();
			//fWriter.close();
			//System.out.println("file was created/saved");
		}
		catch(Exception e)
		{
			System.out.println("fix the error");
		}

        //decryption happens (where Bob is)
        try {
			FileReader fr = new FileReader("sigtext.txt");
			BufferedReader br = new BufferedReader(fr);
			String str;
			
			while((str = br.readLine()) != null)
			{
				System.out.println(str);
		        String decipheredMessage = decrypt(cipherText, pair.getPrivate());
				//System.out.println(decryptedText);
			}
			br.close();
			}
			catch (Exception e) {
				System.out.println("File not found");
			}
      
        //calculating signatures
        long startTime = System.nanoTime();
        for(int i = 0; i < 100; i++)
        {
        	String s = sign("foobar", pair.getPrivate());
        	writer.write(s);
        }
        long stopTime = System.nanoTime();
        long elapsedTime = stopTime -startTime;
        long average_sign = elapsedTime/100;
        System.out.println("Average Time For Signing: " + average_sign + " nanoseconds");
        String s = sign("foobar", pair.getPrivate());//signing happens
        writer.write(s);//s for signature
        writer.close();
		fWriter.close();
		
		//calculating verification
        long start = System.nanoTime();
        for(int i = 0; i < 100; i++)
        {
        	boolean isCorrect = verify("foobar", s, pair.getPublic());
        
        //System.out.println("Signature correct: " + isCorrect);
        }
        long stop = System.nanoTime();
        long elapsed = stop - start;
        long average_verify = elapsed/100;
        System.out.println("Average Time For Verification: " + average_verify + " nanoseconds");
    }
}