package in.memory.decryptor;

import java.io.File;
import java.util.List;

public interface Encryptor {

	/**
	 * Encrypts files by password and creates embedded encryption
	 * 
	 * @param password password for encryption
	 * @param sourceFiles list of source files
	 * @param fileOutputDirectory output directory for encrypted files
	 * @param encryptionOutputDirectory output directory for embedded encryption
	 * @throws Exception
	 */
	void encrypt(final String password, final List<File> sourceFiles, final File fileOutputDirectory,
			final File encryptionOutputDirectory) throws Exception;
}
