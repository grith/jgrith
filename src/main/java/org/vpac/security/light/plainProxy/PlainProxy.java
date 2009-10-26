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

package org.vpac.security.light.plainProxy;

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
import org.vpac.security.light.CredentialHelpers;

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

		CoGProperties props = CoGProperties.getDefault();

		X509Certificate userCert = CertUtil.loadCertificate(props
				.getUserCertFile());

		OpenSSLKey key = new BouncyCastleOpenSSLKey(props.getUserKeyFile());

		if (key.isEncrypted()) {
			try {
				key.decrypt(new String(passphrase));
			} catch (GeneralSecurityException e) {
				throw new Exception("Wrong password or other security error");
			}
		}

		PrivateKey userKey = key.getPrivateKey();
		
		return init(userCert, userKey, lifetime_in_hours);

	}

	public static GSSCredential init(X509Certificate userCert, PrivateKey userKey,
			int lifetime_in_hours) throws GeneralSecurityException {

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
//						.getProxyStrength(), props.getProxyLifeTime() * 3600
						.getProxyStrength(), 3600
						* lifetime_in_hours, proxyType, extSet);

		return CredentialHelpers.wrapGlobusCredential(proxy);

	}

}
