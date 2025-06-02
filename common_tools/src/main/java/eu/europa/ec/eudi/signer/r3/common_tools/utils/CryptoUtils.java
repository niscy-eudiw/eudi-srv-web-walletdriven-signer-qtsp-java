/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.common_tools.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CryptoUtils {
	private static final int GCM_IV_LENGTH = 12; // 12 bytes
	private static final int GCM_TAG_LENGTH = 16; // 128 bits
	private static final Logger log = LoggerFactory.getLogger(CryptoUtils.class);

	private final SecretKey secretKey;

	public CryptoUtils(@Autowired CryptoProperties properties) {
		Security.addProvider(new BouncyCastleProvider());
		String keyProperty = properties.getSymmetricSecretKey();
		this.secretKey = new SecretKeySpec(Base64.getDecoder().decode(keyProperty), "AES");
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
			log.error("Error encrypting the value '{}'. {}", value, e.getMessage());
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
			log.error("Error decrypting the value '{}'. {}", encryptedBase64EncodedValue, e.getMessage());
		}
		return null;
	}

}
