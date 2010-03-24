package org.vpac.security.light.control;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.log4j.Logger;
import org.vpac.security.light.Init;

public class VomsesFiles {

	static final Logger myLogger = Logger
	.getLogger(VomsesFiles.class.getName());

	public static final String[] VOMSES_TO_ACTIVATE = new String[] { "ARCS", "ACC" };

	public static final File AVAILABLE_VOMSES_DIR = new File(System
			.getProperty("user.home"), ".glite" + File.separator
			+ "vomses_available");
	public static final File USER_VOMSES_DIR = new File(System
			.getProperty("user.home"), ".glite" + File.separator + "vomses");
	public static final File GLOBAL_VOMSES_DIR = new File(
	"/etc/vomses");

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
	public static void copyVomses() throws Exception {

		if ( GLOBAL_VOMSES_DIR.exists() && GLOBAL_VOMSES_DIR.isDirectory() ) {
			myLogger.info("Using global vomses directory /etc/vomses.");
			return;
		}

		if (!AVAILABLE_VOMSES_DIR.exists() || !USER_VOMSES_DIR.exists()) {
			createVomsesDirectories();
		}

		int BUFFER_SIZE = 8192;
		int count;
		byte data[] = new byte[BUFFER_SIZE];

		InputStream in = Init.class.getResourceAsStream("/vomses.zip");
		ZipInputStream vomsStream = new ZipInputStream(in);

		BufferedOutputStream dest = null;

		try {

			ZipEntry voms = null;

			while ((voms = vomsStream.getNextEntry()) != null) {

				if (!voms.isDirectory()) {

					myLogger.debug("Vomses name: " + voms.getName());
					File vomses_file = new File(AVAILABLE_VOMSES_DIR, voms
							.getName());

					if (!vomses_file.exists() || "ARCS".equals(voms.getName()) ) {
						
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
			}

			for (String vomsFile : VOMSES_TO_ACTIVATE) {
				File source = new File(AVAILABLE_VOMSES_DIR, vomsFile);
				File target = new File(USER_VOMSES_DIR, vomsFile);
				if (target.exists() || "ARCS".equals(source.getName()) || "ACC".equals(source.getName())) {
					copyFile(source, target);
				} else {
					myLogger.error("Could not activate VO: " + vomsFile
							+ ": Vomses file not available.");
				}
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			myLogger.error(e);
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
