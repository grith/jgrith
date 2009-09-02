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

package org.vpac.security.light.certificate;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.globus.common.CoGProperties;
import org.globus.gsi.CertUtil;
import org.globus.gsi.OpenSSLKey;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;

/**
 * Some very low-level helper methods. Just to illustrate how it works.
 * 
 * @author Markus Binsteiner
 * 
 */
public class CertificateHelper {

	static final Logger myLogger = Logger.getLogger(CertificateHelper.class
			.getName());

	/**
	 * Tries to establish where the globus directory is located.
	 * 
	 * @return the default globus directory or $HOME/.globus if it can't be
	 *         determined.
	 */
	public static File getGlobusDir() {
		try {
			File globusDir = getUserCert().getParentFile();
			return globusDir;
		} catch (Exception e) {
			return new File(System.getProperty("user.home"), ".globus");
		}
	}

	/**
	 * Tries to establish where the certificates directory is located.
	 * 
	 * @return the first found certificates directory or
	 *         getGlobusDir()/certificates if not found.
	 */
	public static File getCertificatesDir() {

		try {
			String dir = CoGProperties.getDefault().getCaCertLocations().split(
					",")[0];
			File certDir = new File(dir);
			return certDir;
		} catch (Exception e) {
			File certDir = new File(getGlobusDir(), "certificates");
			return certDir;
		}

	}

	/**
	 * Returns the default user certificate using the cog kit. Beware, this does
	 * not check whether the certificate exists.
	 * 
	 * @return the user's certificate
	 */
	public static File getUserCert() {
		File usercert = new File(CoGProperties.getDefault().getUserCertFile());
		return usercert;
	}

	/**
	 * Returns the default user key using the cog kit. Beware, this does not
	 * check whether the key exists.
	 * 
	 * @return the user's key
	 */
	public static File getUserKey() {
		File userkey = new File(CoGProperties.getDefault().getUserKeyFile());
		return userkey;
	}

	/**
	 * Checks whether all the required globus credentials (e.g. to create a
	 * proxy) exist.
	 * 
	 * @return true - if they do, false - if they do not
	 */
	public static boolean globusCredentialsReady() {

		if (getUserKey().exists() && getUserKey().canRead()
				&& getUserCert().exists() && getUserCert().canRead())
			return true;
		else
			return false;
	}

	/**
	 * Returns the user certificate from the default location (using the cog
	 * defaults).
	 * 
	 * @return the certificate in as X509Certificate or null if there were
	 *         problems with I/O (file permissions, file not found, ...)
	 * @throws GeneralSecurityException
	 *             if there is a problem with the certificate
	 */
	public static X509Certificate getX509UserCertificate()
			throws GeneralSecurityException {

		X509Certificate cert;
		try {
			cert = CertUtil.loadCertificate(getUserCert().toString());
		} catch (IOException e) {
			myLogger.error("Could not load certificate file: "
					+ e.getLocalizedMessage());
			return null;
		}
		return cert;
	}

	/**
	 * Returns the user certificate from the default location (using the cog
	 * defaults).
	 * 
	 * @return the private key of the user.
	 * @throws GeneralSecurityException
	 */
	public static OpenSSLKey getUsersPrivateKey()
			throws GeneralSecurityException {
		BouncyCastleOpenSSLKey key;
		try {
			key = new BouncyCastleOpenSSLKey(getUserKey().toString());
		} catch (IOException e) {
			myLogger.error("Could not load private key file: "
					+ e.getLocalizedMessage());
			return null;
		}
		return key;
	}

	/**
	 * Returns the users key, decrypted with the password provided.
	 * 
	 * @param password
	 *            the password
	 * @return the decrypted key
	 * @throws InvalidKeyException
	 *             if the password was wrong
	 * @throws GeneralSecurityException
	 *             if something is not right with the key
	 */
	public static OpenSSLKey getDecryptedUsersPrivateKey(byte[] password)
			throws InvalidKeyException, GeneralSecurityException {
		OpenSSLKey key = getUsersPrivateKey();
		if (key == null)
			return null;
		key.decrypt(password);
		Arrays.fill(password, Byte.MAX_VALUE);
		return key;
	}

}
