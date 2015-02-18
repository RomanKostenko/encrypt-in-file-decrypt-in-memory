package in.memory.decoder.impl;

import in.memory.decoder.Decryptor;
import in.memory.decoder.util.EncryptorDecryptorUtil;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class DecryptorImpl implements Decryptor {

	public List<ByteArrayOutputStream> decrypt(final String password, final List<File> sourceFiles,
			final File encryptionInputDirectory) throws Exception {
		// Reading the embedded salt
		final FileInputStream saltFis = new FileInputStream(encryptionInputDirectory + File.separator
				+ EncryptorDecryptorUtil.SALT);
		final byte[] salt = new byte[8];
		saltFis.read(salt);
		saltFis.close();

		// Reading the embedded iv
		final FileInputStream ivFis = new FileInputStream(encryptionInputDirectory + File.separator
				+ EncryptorDecryptorUtil.IV);
		final byte[] iv = new byte[16];
		ivFis.read(iv);
		ivFis.close();

		final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		final KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
		final SecretKey tmp = factory.generateSecret(keySpec);
		final SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

		// File decryption
		final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));

		final List<ByteArrayOutputStream> decryptedTargetsInMemory = new ArrayList<ByteArrayOutputStream>();
		for (final File file : sourceFiles) {
			final FileInputStream source = new FileInputStream(file);
			final ByteArrayOutputStream targetInMemory = new ByteArrayOutputStream();

			// Decrypt files
			EncryptorDecryptorUtil.encryptDecrypt(source, targetInMemory, cipher);

			decryptedTargetsInMemory.add(targetInMemory);
		}

		return decryptedTargetsInMemory;
	}

}
