package in.memory.decoder.util;

import java.io.FileInputStream;
import java.io.OutputStream;

import javax.crypto.Cipher;

public class EncryptorDecryptorUtil {

	public static final int BUFFER_SIZE = 1024;

	public static final String SALT = "salt.enc";

	public static final String IV = "iv.enc";

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
				source.close();
			} catch (final Exception e) {
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
