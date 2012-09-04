/* Copyright 2006 VPAC
 * 
 * This file is part of proxy_light.
 * Grix is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.

 * Grix is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with Grix; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package grith.jgrith.plainProxy;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.utils.CredentialHelpers;

import java.io.File;
import java.io.IOException;

import org.globus.common.CoGProperties;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GlobusCredentialException;
import org.globus.util.Util;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LocalProxy {

	static final Logger myLogger = LoggerFactory.getLogger(LocalProxy.class.getName());

	public static final String PROXY_FILE = CoGProperties.getDefault()
			.getProxyFile();

	public static final String CERT_FILE = CoGProperties.getDefault()
			.getUserCertFile();
	public static final String KEY_FILE = CoGProperties.getDefault()
			.getUserKeyFile();

	/**
	 * Writes random data in the default local proxy file and then deletes it.
	 */
	public static void gridProxyDestroy() {

		Util.destroy(CoGProperties.getDefault().getProxyFile());
	}

	/**
	 * Calls gridProxyInit(char[] passwd, int lifetime_in_hours) with a default
	 * lifetime of 12 hours
	 * 
	 * @param passwd
	 *            the passphrase of the private key
	 * @throws Exception
	 *             if some general error occured
	 * @throws GSSException
	 *             if something was wrong with the gsscredential
	 * @throws IOException
	 *             if the proxy could not be written to disk
	 */
	public static void gridProxyInit(char[] passwd) throws IOException,
	GSSException, Exception {

		gridProxyInit(passwd, 12);

	}

	/**
	 * A helper method to do the equivalent of grid-proxy-init in Java. It
	 * creates a proxy from the local usercert/userkey and writes it to disk
	 * (e.g. /tmp/x509up_uXXX on linux).
	 * 
	 * @param passwd
	 *            the passphrase of the private key in the .globus folder
	 * @param lifetime_in_hours
	 *            how long should the proxy be valid for
	 * @throws Exception
	 *             if some general error occured
	 * @throws GSSException
	 *             if something was wrong with the gsscredential
	 * @throws IOException
	 *             if the proxy could not be written to disk
	 */
	public static void gridProxyInit(char[] passwd, int lifetime_in_hours)
			throws CredentialException {

		GSSCredential credential = PlainProxy.init(passwd, lifetime_in_hours);

		// get the default location of the grid-proxy file
		File proxyFile = new File(CoGProperties.getDefault().getProxyFile());
		// write the proxy to disk
		CredentialHelpers.writeToDisk(credential, proxyFile);
	}

	/**
	 * A helper method to do the equivalent of grid-proxy-init in Java. It
	 * creates a proxy from the specified usercert/userkey and writes it to disk
	 * (e.g. /tmp/x509up_uXXX on linux).
	 * 
	 * @param certFile
	 *            the certificate file path
	 * @param keyFile
	 *            the key file path
	 * @param passwd
	 *            the passphrase of the private key in the .globus folder
	 * @param lifetime_in_hours
	 *            how long should the proxy be valid for
	 * @throws CredentialException
	 *             if the proxy could not be created and written to disk
	 */
	public static void gridProxyInit(String certFile, String keyFile, char[] passwd, int lifetime_in_hours)
			throws CredentialException {

		try {
			GSSCredential credential = PlainProxy.init(certFile, keyFile, passwd,
					lifetime_in_hours);

			// get the default location of the grid-proxy file
			File proxyFile = new File(CoGProperties.getDefault().getProxyFile());
			// write the proxy to disk
			CredentialHelpers.writeToDisk(credential, proxyFile);
		} catch (Exception e1) {
			throw new CredentialException(e1);
		}
	}

	/**
	 * Loads the local proxy into a {@link GlobusCredential}.
	 * 
	 * @return the credential
	 * @throws GlobusCredentialException
	 */
	public static GlobusCredential loadGlobusCredential()
			throws GlobusCredentialException {
		GlobusCredential globusCredential = null;

		// String jobProxy = System.getenv("X509_USER_PROXY");
		// if (StringUtils.isNotBlank(jobProxy)) {
		//
		// globusCredential = new GlobusCredential(jobProxy);
		//
		// } else {

		globusCredential = new GlobusCredential(CoGProperties.getDefault()
				.getProxyFile());
		// }

		return globusCredential;
	}

	/**
	 * Loads the local proxy into a {@link GSSCredential}.
	 * 
	 * @return the credential
	 * @throws GlobusCredentialException
	 *             if something goes wrong
	 */
	public static GSSCredential loadGSSCredential()
			throws GlobusCredentialException {

		return CredentialHelpers.wrapGlobusCredential(loadGlobusCredential());
	}

	/**
	 * Checks whether there is a local grid proxy on the default location
	 * 
	 * @return true - if there is, false - if there is not a valid proxy
	 */
	public static boolean validGridProxyExists() {

		GlobusCredential globusCredential = null;
		try {
			globusCredential = new GlobusCredential(CoGProperties.getDefault()
					.getProxyFile());
			globusCredential.verify();
		} catch (GlobusCredentialException e) {
			// no. not valid.
			myLogger.info("Checked Local grid proxy - Not valid: "
					+ e.getMessage());
			return false;
		}
		// ok. valid grid proxy.
		return true;
	}

	/**
	 * Checks whether there is a local grid proxy on the default location
	 * 
	 * @param minTimeInMinutes
	 *            minimum time the credential should be valid for
	 * 
	 * @return true - if there is and it's lifetime >= the specified min time,
	 *         false - if there is not a valid proxy or the lifetime is shorter
	 */
	public static boolean validGridProxyExists(int minTimeInMinutes) {

		String location = CoGProperties.getDefault().getProxyFile();

		GlobusCredential globusCredential = null;
		try {
			globusCredential = new GlobusCredential(location);
			globusCredential.verify();

			if ((globusCredential.getTimeLeft() / 60) < minTimeInMinutes) {
				return false;
			} else {
				return true;
			}

		} catch (GlobusCredentialException e) {
			// no. not valid.
			myLogger.info("Checked Local grid proxy - Not valid: "
					+ e.getMessage());
			return false;
		}
	}

}
