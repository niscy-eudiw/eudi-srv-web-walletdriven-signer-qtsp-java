package eu.europa.ec.eudi.signer.r3.common_tools.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoUtils {
	private static final int GCM_IV_LENGTH = 12; // 12 bytes
	private static final int GCM_TAG_LENGTH = 16; // 128 bits

	private final SecretKey secretKey;

	public CryptoUtils() throws Exception{
		Security.addProvider(new BouncyCastleProvider());

		Properties properties = new Properties();
		InputStream configStream = getClass().getClassLoader().getResourceAsStream("application-crypto.yml");
		properties.load(configStream);

		System.out.println(properties.get("symmetric-secret-key"));

		/*KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		SecretKey s = keyGenerator.generateKey();
		System.out.println(Base64.getEncoder().encodeToString(s.getEncoded()));
		*/
		this.secretKey = new SecretKeySpec(Base64.getDecoder().decode(properties.get("symmetric-secret-key").toString()), "AES");
	}


	public String encryptString(String value){
		byte[] iv = new byte[GCM_IV_LENGTH];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(iv);

		byte[] encryptedSecretKeyBytes;
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec algSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

			cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, algSpec);
			encryptedSecretKeyBytes = cipher.doFinal(value.getBytes());

			ByteBuffer byteBuffer = ByteBuffer.allocate(GCM_IV_LENGTH + encryptedSecretKeyBytes.length);
			byteBuffer.put(iv);
			byteBuffer.put(encryptedSecretKeyBytes);
			return Base64.getEncoder().encodeToString(byteBuffer.array());
		}
		catch (Exception e){
			e.printStackTrace();
		}
		return null;
	}

	public String decryptString(String encryptedBase64EncodedValue){
		byte[] encryptedBytesValue = Base64.getDecoder().decode(encryptedBase64EncodedValue);
		ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedBytesValue);

		byte[] iv = new byte[GCM_IV_LENGTH];
		byteBuffer.get(iv);
		byte[] encryptedBytes = new byte[byteBuffer.remaining()];
		byteBuffer.get(encryptedBytes);

		try {
			// decrypts the secret key
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec algSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

			cipher.init(Cipher.DECRYPT_MODE, this.secretKey, algSpec);
			byte[] valueBytes = cipher.doFinal(encryptedBytes);

			return new String(valueBytes);
		}
		catch (Exception e){
			e.printStackTrace();
		}
		return null;
	}

}
