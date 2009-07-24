package org.vpac.security.light.control;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.log4j.Logger;
import org.globus.common.CoGProperties;
import org.vpac.security.light.Init;
import org.vpac.security.light.certificate.CertificateHelper;

public class CertificateFiles {
	
	static final Logger myLogger = Logger.getLogger(Init.class.getName());

	/**
	 * Creates the globus directory if it doesn't exist yet.
	 * @throws Exception if something goes wrong
	 */
	public static void createGlobusDirectory() throws Exception {
		
		File globusDir = CertificateHelper.getGlobusDir();
		
		if ( ! globusDir.exists() ) {
			if ( ! globusDir.mkdirs() ) {
				myLogger.error("Could not create globus directory.");
				throw new Exception("Could not create globus directory. Please set permissions for "+globusDir.toString()+" to be created.");
			}
		}
	}
	
	/**
	 * Creates the certificates directory if it doesn't exist yet
	 * @throws Exception if something goes wrong
	 */
	public static void createCertificatesDirectory() throws Exception {
		
		File certDir = CertificateHelper.getCertificatesDir();
		if ( ! certDir.exists() ) {
			if ( ! certDir.mkdirs() ) {
				myLogger.error("Could not create certificates directory");
				throw new Exception("Could not create certificates directory. Please set permissions for "+certDir.toString()+" to be created");
			}
		}
		
	}
	
	/**
	 * This one copies the CA certificates (in the certificates.zip file) into the .globus/certificates
	 * directory if they are not already there...
	 * @throws Exception 
	 * 
	 */
	public static void copyCACerts() throws Exception {

		createGlobusDirectory();

		createCertificatesDirectory();
		
		File certDir = CertificateHelper.getCertificatesDir();
		
		int BUFFER_SIZE = 8192;
		int count;
		byte data[] = new byte[BUFFER_SIZE];

		InputStream in = Init.class.getResourceAsStream("/certificates.zip");
		ZipInputStream certStream = new ZipInputStream(in);

		BufferedOutputStream dest = null;

		try {

			ZipEntry cert = null;

			while ((cert = certStream.getNextEntry()) != null) {

				if (!cert.isDirectory()) {

					myLogger.debug("Certificate name: " + cert.getName());
					File cert_file = new File(certDir, cert.getName());

					// exception for the apacgrid cert
					if (!cert_file.exists() || cert_file.getName().startsWith("1e12d831")) {

						// Write the file to the file system
						FileOutputStream fos = new FileOutputStream(cert_file);
						dest = new BufferedOutputStream(fos, BUFFER_SIZE);
						while ((count = certStream.read(data, 0, BUFFER_SIZE)) != -1) {
							dest.write(data, 0, count);
						}
						dest.flush();
						dest.close();
					}

				}
			}

		} catch (IOException e) {
			myLogger.warn(e.getLocalizedMessage());
			throw new Exception("Could not write certificate: "+e.getLocalizedMessage(), e);
		}
	}
	
}
