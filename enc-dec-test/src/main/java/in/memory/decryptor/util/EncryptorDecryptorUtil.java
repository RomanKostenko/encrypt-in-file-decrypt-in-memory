package in.memory.decryptor.util;

import java.io.FileInputStream;
import java.io.OutputStream;

import javax.crypto.Cipher;

public class EncryptorDecryptorUtil {

	// The size of buffer for copying from source to target
	public static final int BUFFER_SIZE = 1024;

	// The file name of salt
	public static final String SALT = "salt.enc";

	// The file name of iv
	public static final String IV = "iv.enc";

	/**
	 * Encrypts of decrypts file.<br>
	 * If cipher was created in <code>Cipher.ENCRYPT_MODE</code> the file will be encrypted.<br>
	 * In opposite way if If cipher has <code>Cipher.DECRYPT_MODE</code> the file will be decrypted.
	 * 
	 * @param source file for encryption or decryption
	 * @param target in memory byte array or another output stream which will keep result
	 * @param cipher chiper with <code>Cipher.ENCRYPT_MODE</code> or <code>Cipher.DECRYPT_MODE</code> mode
	 * @throws Exception
	 */
	public static void encryptDecrypt(final FileInputStream source, final OutputStream target, final Cipher cipher)
			throws Exception {

		final byte[] input = new byte[EncryptorDecryptorUtil.BUFFER_SIZE];
		int bytesRead;

		try {
			while ((bytesRead = source.read(input)) != -1) {
				final byte[] output = cipher.update(input, 0, bytesRead);
				if (output != null) {
					target.write(output);
				}
			}
		} finally {
			try {
				// Try to close source stream after work
				source.close();
			} catch (final Exception e) {
				// In case of exception try to close target stream
				target.close();
				throw e;
			}
		}

		try {
			final byte[] output = cipher.doFinal();
			if (output != null) {
				target.write(output);
			}
			target.flush();
		} finally {
			target.close();
		}

	}
}
