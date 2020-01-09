import javax.crypto.Cipher;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

import static java.nio.charset.StandardCharsets.UTF_8;//RSA 2048
//RSADig
public class Program5 {
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }
    
    public static KeyPair getKeyPairFromKeyStore() throws Exception {
        InputStream ins = Program5.class.getResourceAsStream("/keystore.jks");
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
    	
        //get key pair
        KeyPair pair = generateKeyPair();
        //KeyPair pair = getKeyPairFromKeyStore();

        //encrypt (where Alice is)
        System.out.println("Original Message: ");
		Scanner originalString = new Scanner(System.in);
		String m = originalString.nextLine();//m is message
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

        //sign message
        String s = sign("smiles", pair.getPrivate());//s equals signature
        System.out.println(s);
        writer.write(s);//write it to file
        writer.close();
        fWriter.close();
        
        //verify signature
        boolean isCorrect = verify("smiles", s, pair.getPublic());
        System.out.println("Signature correct: " + isCorrect);
    }
}