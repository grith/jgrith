package grith.jgrith.utils;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.python.google.common.collect.Sets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VomsesFiles {

	static final Logger myLogger = LoggerFactory.getLogger(VomsesFiles.class
			.getName());

	public static final Set<String> DEFAULT_VOS = Sets.newHashSet("nz");

	// public static final String[] VOMSES_TO_ACTIVATE = new String[] { "nz" };

	public static final File AVAILABLE_VOMSES_DIR = new File(
			System.getProperty("user.home"), ".glite" + File.separator
			+ "vomses_available");
	public static final File USER_VOMSES_DIR = new File(
			System.getProperty("user.home"), ".glite" + File.separator
			+ "vomses");
	public static final File GLOBAL_VOMSES_DIR = new File("/etc/vomses");

	public static void copyFile(File in, File out) throws IOException {
		FileChannel inChannel = new FileInputStream(in).getChannel();
		FileChannel outChannel = new FileOutputStream(out).getChannel();
		try {
			inChannel.transferTo(0, inChannel.size(), outChannel);
		} catch (IOException e) {
			throw e;
		} finally {
			if (inChannel != null) {
				inChannel.close();
			}
			if (outChannel != null) {
				outChannel.close();
			}
		}
	}

	/**
	 * Extracts the files in the vomses.zip file in the directory
	 * $HOME/.glite/vomses These files are pointing Grix to the voms/vomrs
	 * server(s) the APACGrid is using.
	 * 
	 * @throws Exception
	 */
	public static void copyVomses(Collection<String> vomses_to_use)
			throws Exception {

		if (GLOBAL_VOMSES_DIR.exists() && GLOBAL_VOMSES_DIR.isDirectory()) {
			myLogger.info("Using global vomses directory /etc/vomses.");
			return;
		}

		if (!AVAILABLE_VOMSES_DIR.exists() || !USER_VOMSES_DIR.exists()) {
			createVomsesDirectories();
		}

		int BUFFER_SIZE = 8192;
		int count;
		byte data[] = new byte[BUFFER_SIZE];

		InputStream in = VomsesFiles.class.getResourceAsStream("/vomses.zip");
		ZipInputStream vomsStream = new ZipInputStream(in);

		BufferedOutputStream dest = null;

		boolean add_all = false;
		if (vomses_to_use == null) {
			add_all = true;
			vomses_to_use = new HashSet<String>();
		}

		try {

			ZipEntry voms = null;

			while ((voms = vomsStream.getNextEntry()) != null) {

				if (!voms.isDirectory()) {

					myLogger.debug("Vomses name: " + voms.getName());
					File vomses_file = new File(AVAILABLE_VOMSES_DIR,
							voms.getName());

					if (add_all) {
						vomses_to_use.add(voms.getName());
					}
					// Write the file to the file system
					FileOutputStream fos = new FileOutputStream(vomses_file);
					dest = new BufferedOutputStream(fos, BUFFER_SIZE);
					while ((count = vomsStream.read(data, 0, BUFFER_SIZE)) != -1) {
						dest.write(data, 0, count);
					}
					dest.flush();
					dest.close();
				}

			}

			for (String vomsFile : vomses_to_use) {
				File source = new File(AVAILABLE_VOMSES_DIR, vomsFile);
				File target = new File(USER_VOMSES_DIR, vomsFile);
				if (source.exists()) {
					copyFile(source, target);
				} else {
					myLogger.error("Could not activate VO: " + vomsFile
							+ ": Vomses file not available.");
				}
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			myLogger.error("Can't copy vomses files.", e);
		}
	}

	/**
	 * Creates the globus directory if it doesn't exist yet.
	 * 
	 * @throws Exception
	 *             if something goes wrong
	 */
	public static void createVomsesDirectories() throws Exception {

		if (!USER_VOMSES_DIR.exists()) {
			if (!USER_VOMSES_DIR.mkdirs()) {
				myLogger.error("Could not create vomses directory.");
				throw new Exception(
						"Could not create vomses directory. Please set permissions for "
								+ USER_VOMSES_DIR.toString()
								+ " to be created.");
			}
		}

		if (!AVAILABLE_VOMSES_DIR.exists()) {
			if (!AVAILABLE_VOMSES_DIR.mkdirs()) {
				myLogger.error("Could not create available_vomses directory.");
				throw new Exception(
						"Could not create vomses directory. Please set permissions for "
								+ AVAILABLE_VOMSES_DIR.toString()
								+ " to be created.");
			}
		}
	}

}
