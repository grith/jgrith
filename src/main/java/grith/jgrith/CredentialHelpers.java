/* Copyright 2006 VPAC
 * 
 * This file is part of proxy_light.
 * proxy_light is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.

 * proxy_light is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with proxy_light; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package grith.jgrith;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.plainProxy.LocalProxy;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GlobusCredentialException;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.globus.util.Util;
import org.gridforum.jgss.ExtendedGSSCredential;
import org.gridforum.jgss.ExtendedGSSManager;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CredentialHelpers {

	static final Logger myLogger = LoggerFactory.getLogger(CredentialHelpers.class
			.getName());

	public static GSSCredential convertByteArrayToGSSCredential(byte[] data)
			throws GSSException {
		ExtendedGSSManager manager = (ExtendedGSSManager) ExtendedGSSManager
				.getInstance();
		GSSCredential credential = manager.createCredential(
				data, // proxy data
				ExtendedGSSCredential.IMPEXP_OPAQUE,
				GSSCredential.DEFAULT_LIFETIME, null, // OID Mechanism
				GSSCredential.INITIATE_AND_ACCEPT);

		return credential;
	}

	public static byte[] convertGSSCredentialToByteArray(GSSCredential gssCred)
			throws GSSException {
		byte[] data = ((ExtendedGSSCredential) gssCred)
				.export(ExtendedGSSCredential.IMPEXP_OPAQUE);
		return data;

	}

	/**
	 * Loads a GlobusCredential from a file. This method is really trivial and I
	 * only included it to have everything in one place.
	 * 
	 * @param proxyFile
	 *            the proxy file
	 * @return the {@link GlobusCredential}
	 * @throws CredentialException
	 *             if something goes wrong (e.g. the proxy is not a
	 *             GlobusCredential
	 */
	public static GlobusCredential loadGlobusCredential(File proxyFile)
			throws CredentialException {
		try {
			return new GlobusCredential(proxyFile.toString());
		} catch (GlobusCredentialException e) {
			throw new CredentialException(e);
		}
	}

	public static GSSCredential loadGssCredential(File proxyFile)
			throws CredentialException {
		return wrapGlobusCredential(loadGlobusCredential(proxyFile));
	}

	/**
	 * Returns the wrapped {@link GlobusCredential} of a {@link GSSCredential}
	 * object
	 * 
	 * @param gss
	 *            the {@link GSSCredential} (has to be of type
	 *            {@link GlobusGSSCredentialImpl}
	 * @return the wrapped {@link GlobusCredential} of a {@link GSSCredential}
	 *         object or null if the credential object is not of type
	 *         {@link GlobusGSSCredentialImpl}
	 */
	public static GlobusCredential unwrapGlobusCredential(GSSCredential gss) {

		GlobusCredential globusCred = null;
		if (gss instanceof GlobusGSSCredentialImpl) {
			globusCred = ((GlobusGSSCredentialImpl) gss).getGlobusCredential();
		}
		return globusCred;
	}

	/**
	 * Wraps a {@link GlobusCredential} in a {@link GSSCredential}
	 * 
	 * @param globusCred
	 *            the credential to wrap in a {@link GSSCredential}
	 * @return a {@link GSSCredential} object that contains the
	 *         {@link GlobusCredential} (the implementation class is
	 *         {@link GlobusGSSCredentialImpl})
	 */
	public static GSSCredential wrapGlobusCredential(GlobusCredential globusCred) {

		GSSCredential gss;

		try {
			gss = new GlobusGSSCredentialImpl(globusCred,
					GSSCredential.INITIATE_AND_ACCEPT);
		} catch (GSSException e) {
			myLogger.error("Could not wrap GlobusCredential: " + e.getMessage());
			return null;
		}

		return gss;
	}

	/**
	 * Writes the specified globus credential to the default globus location on
	 * the local machine.
	 * 
	 * @param globusCred
	 *            the credential
	 * @throws IOException
	 *             if something goes wrong
	 */
	public static void writeToDisk(GlobusCredential globusCred)
			throws IOException {

		writeToDisk(globusCred, new File(LocalProxy.PROXY_FILE));

	}

	/**
	 * Writes the specified globus credential to disk.
	 * 
	 * @param globusCred
	 *            the credential
	 * @param proxyFile
	 *            the file to store the credential to (use
	 *            CoGProperties.getDefault().getProxyFile() for the default
	 *            globus proxy location
	 * @throws IOException
	 *             if something goes wrong
	 */
	public static void writeToDisk(GlobusCredential globusCred, File proxyFile)
			throws IOException {

		OutputStream out = null;
		myLogger.debug("Save proxy file: " + proxyFile);
		try {
			out = new FileOutputStream(proxyFile);
			globusCred.save(out);
			Util.setFilePermissions(proxyFile.toString(), 600);
		} catch (FileNotFoundException e) {
			myLogger.error("Could not write credential to file "
					+ proxyFile.getAbsolutePath() + ": " + e.getMessage());
			throw new IOException(e.getMessage());
		} finally {
			if (out != null) {
				try {
					out.close();
				} catch (IOException e) {
					myLogger.error("Could not write credential to file "
							+ proxyFile.getAbsolutePath() + ": "
							+ e.getMessage());
					throw e;
				}
			}
		}
	}

	/**
	 * Writes a GSSCredential to the default globus location
	 * 
	 * @param gssCred
	 *            the credential
	 * @throws GSSException
	 *             if something is strange with the {@link GSSCredential}
	 * @throws IOException
	 *             if something's wonky with the file / file permission
	 */
	public static void writeToDisk(GSSCredential gssCred)
			throws CredentialException {
		writeToDisk(gssCred, new File(LocalProxy.PROXY_FILE));
	}

	/**
	 * Writes a GSSCredential to disk
	 * 
	 * @param gssCred
	 *            the credential
	 * @param proxyFile
	 *            the file you want to save the credential to
	 * @throws IOException
	 *             if something's wonky with the file / file permission
	 * @throws GSSException
	 *             if something is strange with the {@link GSSCredential}
	 */
	public static void writeToDisk(GSSCredential gssCred, File proxyFile)
			throws CredentialException {

		byte[] data;
		try {
			data = convertGSSCredentialToByteArray(gssCred);

			String path = proxyFile.getPath();

			FileOutputStream out = new FileOutputStream(path);
			out.write(data);
			Util.setFilePermissions(proxyFile.toString(), 600);
		} catch (Exception e) {
			throw new CredentialException(e);
		}
	}

}
