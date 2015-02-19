package in.memory.decryptor;

import in.memory.decryptor.Decryptor;
import in.memory.decryptor.Encryptor;
import in.memory.decryptor.impl.DecryptorImpl;
import in.memory.decryptor.impl.EncryptorImpl;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class EncryptorDecryptorTest {

	public Encryptor encryptor = new EncryptorImpl();
	public Decryptor decryptor = new DecryptorImpl();

	@BeforeClass
	public static void setUp() {
		final File encryptedfileOutputDirectory = new File("encryptedfileOutputDirectory");
		if (encryptedfileOutputDirectory.exists()) {
			for (final File file : encryptedfileOutputDirectory.listFiles()) {
				file.delete();
			}
		}

		final File encryptionOutputDirectory = new File("encryptionOutputDirectory");
		if (encryptionOutputDirectory.exists()) {
			for (final File file : encryptionOutputDirectory.listFiles()) {
				file.delete();
			}
		}
	}

	@Test
	public void test() throws Exception {
		// Prepare list of files to encryption
		final File textFile = new File(getClass().getClassLoader().getResource("plainfile.txt").getFile());

		final List<File> toEncryptFiles = new ArrayList<File>();
		// We will encrypt text file
		toEncryptFiles.add(textFile);

		// Prepare output directory for encrypted files
		final File encryptedfileOutputDirectory = new File("encryptedfileOutputDirectory");
		if (!encryptedfileOutputDirectory.exists()) {
			encryptedfileOutputDirectory.mkdir();
		}

		// Prepare output directory for embedded encryption
		final File encryptionOutputDirectory = new File("encryptionOutputDirectory");
		if (!encryptionOutputDirectory.exists()) {
			encryptionOutputDirectory.mkdir();
		}

		// Encrypt text file!
		encryptor.encrypt("MyHardPassword", toEncryptFiles, encryptedfileOutputDirectory, encryptionOutputDirectory);

		// Check salt encryption
		final File embeddedSalt = new File("encryptionOutputDirectory" + File.separator + "salt.enc");
		Assert.assertTrue(embeddedSalt.exists());

		// Check iv encryption
		final File embeddedIv = new File("encryptionOutputDirectory" + File.separator + "iv.enc");
		Assert.assertTrue(embeddedIv.exists());

		// Check encrypted text file
		final File encryptedTextFile = new File("encryptedfileOutputDirectory" + File.separator + "plainfile.txt");
		Assert.assertTrue(encryptedTextFile.exists());

		// Prepare list for decryption
		final List<File> toDecryptFiles = new ArrayList<File>();
		toDecryptFiles.add(encryptedTextFile);

		// Decrypt and get in memory list of decrypted files
		final List<ByteArrayOutputStream> decryptedFilesInMemory = decryptor.decrypt("MyHardPassword", toDecryptFiles,
				encryptionOutputDirectory);

		Assert.assertEquals(1, decryptedFilesInMemory.size());

		// The file in memory, not in the file
		final ByteArrayOutputStream decryptedTextFileInMemory = decryptedFilesInMemory.get(0);

		// Check text content
		final String testContent = new String(decryptedTextFileInMemory.toByteArray());
		Assert.assertEquals("qwertyuiop1234567890", testContent);

		System.out.println(testContent);
	}

}
