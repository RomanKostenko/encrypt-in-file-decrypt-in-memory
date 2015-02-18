package in.memory.decoder.impl;

import in.memory.decoder.Encryptor;
import in.memory.decoder.util.EncryptorDecryptorUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptorImpl implements Encryptor {

	public void encrypt(final String password, final List<File> sourceFiles, final File fileOutputDirectory,
			final File encryptionOutputDirectory) throws Exception {
		final byte[] salt = new byte[8];
		final SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(salt);

		// Salt is used for encoding. Embed it into secure directory
		final FileOutputStream saltOutFile = new FileOutputStream(new File(encryptionOutputDirectory + File.separator
				+ EncryptorDecryptorUtil.SALT));
		saltOutFile.write(salt);
		saltOutFile.close();

		final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		final KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
		final SecretKey secretKey = factory.generateSecret(keySpec);
		final SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

		final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secret);
		final AlgorithmParameters params = cipher.getParameters();

		// iv adds randomness to the text and just makes the mechanism more secure
		// Embed it into secure directory
		final FileOutputStream ivOutFile = new FileOutputStream(encryptionOutputDirectory + File.separator
				+ EncryptorDecryptorUtil.IV);
		final byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
		ivOutFile.write(iv);
		ivOutFile.close();

		// Encrypt files
		for (final File file : sourceFiles) {
			final FileInputStream source = new FileInputStream(file);
			final FileOutputStream target = new FileOutputStream(fileOutputDirectory + File.separator + file.getName());

			// Decrypt files
			EncryptorDecryptorUtil.encryptDecrypt(source, target, cipher);
		}
	}

}
