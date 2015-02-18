package in.memory.decoder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.List;

public interface Decryptor {
	/**
	 * Decrypts files by password and embedded encryption
	 * 
	 * @param password
	 *            password for decryption
	 * @param sourceFiles
	 *            encrypted files
	 * @param encryptionInputDirectory
	 *            directory which contains encryption assets
	 * @return in memory list of decrypted files
	 * @throws Exception
	 */
	List<ByteArrayOutputStream> decrypt(final String password, final List<File> sourceFiles,
			final File encryptionInputDirectory) throws Exception;
}
