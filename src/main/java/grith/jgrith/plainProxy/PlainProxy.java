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

package grith.jgrith.plainProxy;

import grith.jgrith.CredentialHelpers;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.globus.common.CoGProperties;
import org.globus.gsi.CertUtil;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.OpenSSLKey;
import org.globus.gsi.X509ExtensionSet;
import org.globus.gsi.bc.BouncyCastleCertProcessingFactory;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
import org.globus.gsi.bc.BouncyCastleX509Extension;
import org.globus.gsi.proxy.ext.GlobusProxyCertInfoExtension;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;
import org.ietf.jgss.GSSCredential;

public class PlainProxy {

	static final Logger myLogger = Logger.getLogger(PlainProxy.class.getName());

	/**
	 * Creates a {@link GSSCredential} using all the (cog-) defaults like cert
	 * in $HOME/.globus/usercert.pem...
	 * 
	 * @param passphrase
	 *            the passphrase of your private key
	 * @param lifetime_in_hours
	 *            the lifetime of the proxy
	 * @return the proxy
	 * @throws Exception
	 *             if something has gone wrong
	 */
	public static GSSCredential init(char[] passphrase, int lifetime_in_hours)
			throws Exception {
		return init_lifetimeInSeconds(passphrase, lifetime_in_hours * 3600);
	}

	/**
	 * Creates a {@link GSSCredential}
	 * 
	 * @param certFile
	 *            the certificate file path
	 * @param keyFile
	 *            the key file path
	 * @param passphrase
	 *            the passphrase of your private key
	 * @param lifetime_in_hours
	 *            the lifetime of the proxy
	 * @return the proxy
	 * @throws Exception
	 *             if something has gone wrong
	 */

	public static GSSCredential init(String certFile, String keyFile,
			char[] passphrase, int lifetime_in_hours) throws Exception {
		return init_lifetimeInSeconds(certFile, keyFile, passphrase,
				lifetime_in_hours * 3600);
	}

	public static GSSCredential init(X509Certificate userCert,
			PrivateKey userKey, int lifetime_in_hours)
					throws GeneralSecurityException {

		return init_lifetimeInSeconds(userCert, userKey,
				lifetime_in_hours * 3600);
	}

	public static GSSCredential init_lifetimeInSeconds(char[] passphrase,
			int lifetime_in_seconds)
			throws Exception {

		CoGProperties props = CoGProperties.getDefault();

		return init_lifetimeInSeconds(props.getUserCertFile(),
				props.getUserKeyFile(), passphrase, lifetime_in_seconds);

	}
	public static GSSCredential init_lifetimeInSeconds(String certFile, String keyFile,
			char[] passphrase, int lifetime_in_seconds) throws Exception {

		X509Certificate userCert = CertUtil.loadCertificate(certFile);

		OpenSSLKey key = new BouncyCastleOpenSSLKey(keyFile);

		if (key.isEncrypted()) {
			try {
				key.decrypt(new String(passphrase));
			} catch (GeneralSecurityException e) {
				throw new Exception("Wrong password or other security error");
			}
		}

		PrivateKey userKey = key.getPrivateKey();

		return init_lifetimeInSeconds(userCert, userKey, lifetime_in_seconds);

	}

	public static GSSCredential init_lifetimeInSeconds(
			X509Certificate userCert, PrivateKey userKey,
			int lifetime_in_seconds) throws GeneralSecurityException {

		CoGProperties props = CoGProperties.getDefault();

		BouncyCastleCertProcessingFactory factory = BouncyCastleCertProcessingFactory
				.getDefault();

		int proxyType = GSIConstants.GSI_2_PROXY;
		// int proxyType = GSIConstants.GSI_3_IMPERSONATION_PROXY;

		ProxyPolicy policy = new ProxyPolicy(ProxyPolicy.IMPERSONATION);
		ProxyCertInfo proxyCertInfo = new ProxyCertInfo(policy);

		BouncyCastleX509Extension certInfoExt = new GlobusProxyCertInfoExtension(
				proxyCertInfo);

		X509ExtensionSet extSet = null;
		if (proxyCertInfo != null) {
			extSet = new X509ExtensionSet();

			// old OID
			extSet.add(new GlobusProxyCertInfoExtension(proxyCertInfo));
		}

		GlobusCredential proxy = factory.createCredential(
				new X509Certificate[] { userCert }, userKey, props
				// .getProxyStrength(), props.getProxyLifeTime() * 3600
				.getProxyStrength(), lifetime_in_seconds,
				proxyType, extSet);

		return CredentialHelpers.wrapGlobusCredential(proxy);

	}

}
