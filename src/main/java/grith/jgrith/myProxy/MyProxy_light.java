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

package grith.jgrith.myProxy;

import grith.jgrith.Environment;
import grith.jgrith.utils.CredentialHelpers;

import org.apache.commons.lang.StringUtils;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is really only to show how to upload/retrieve a MyProxy
 * credential. Just copy & paste the lines you need into your code.
 * 
 * @author markus
 * 
 */
public class MyProxy_light {

	static final Logger myLogger = LoggerFactory.getLogger(MyProxy_light.class
			.getName());

	/**
	 * The default lifetime of a delegated proxy (12 hours).
	 */
	public static int PROXY_LIFETIME_DEFAULT = 12 * 60 * 60;

	/**
	 * Retrieves a {@link GSSCredential} from a myproxy server using username &
	 * password. This method is used if you want to retrieve a proxy that
	 * requires authentication.
	 * 
	 * @param myproxyServer
	 *            the hostname of the myproxy server
	 * @param myproxyPort
	 *            the port of the myproxy server (default is 443)
	 * @param credential
	 *            the credential that is used to authenticate against the
	 *            MyProxy server
	 * @param username
	 *            the username the user used when uploading the proxy
	 * @param passphrase
	 *            the passphrase the user used when uploading the proxy
	 * @param lifetime_in_seconds
	 *            how long you want the proxy to be valid
	 * @return the delegated credential
	 * @throws MyProxyException
	 *             if something did not work
	 */
	public static GSSCredential getDelegation(String myproxyServer,
			int myproxyPort, GSSCredential credential, String username,
			char[] passphrase, int lifetime_in_seconds) throws MyProxyException {

		MyProxy myproxy = getMyProxy(myproxyServer, myproxyPort);
		GSSCredential proxyCredential = null;
		try {
			proxyCredential = myproxy.get(credential, username, new String(
					passphrase), lifetime_in_seconds);
		} catch (MyProxyException e) {
			LocalMyProxy.myLogger
			.error("Could not get delegated proxy from server \""
					+ myproxyServer + ":" + myproxyPort + ": "
					+ e.getMessage());
			throw e;
		}
		return proxyCredential;
	}

	/**
	 * Retrieves a {@link GSSCredential} from a myproxy server using username &
	 * password. This method is used when you want to retrieve a proxy that has
	 * got the "allow anonymous retriever) flag enabled.
	 * 
	 * @param myproxyServer
	 *            the hostname of the myproxy server
	 * @param myproxyPort
	 *            the port of the myproxy server (default is 443)
	 * @param username
	 *            the username the user used when uploading the proxy
	 * @param passphrase
	 *            the passphrase the user used when uploading the proxy
	 * @param lifetime_in_secs
	 *            how long you want the proxy to be valid
	 * @return the delegated credential
	 * @throws MyProxyException
	 *             if something did not work
	 */
	public static GSSCredential getDelegation(String myproxyServer,
			int myproxyPort, String username, char[] passphrase,
			int lifetime_in_secs) throws MyProxyException {
		MyProxy myproxy = getMyProxy(myproxyServer, myproxyPort);
		GSSCredential credential = null;
		try {
			credential = myproxy.get(username, new String(passphrase),
					lifetime_in_secs);
		} catch (MyProxyException e) {
			LocalMyProxy.myLogger
			.error("Could not get delegated proxy from server \""
					+ myproxyServer + ":" + myproxyPort + ": "
					+ e.getMessage());
			throw e;
		}
		return credential;
	}

	public static MyProxy getMyProxy(String myproxyserver, int myproxyPort) {
		if (StringUtils.isBlank(myproxyserver)
				|| "myproxy.arcs.org.au".equals(myproxyserver)
				|| "myproxy2.arcs.org.au".equals(myproxyserver)
				|| "202.158.218.205".equals(myproxyserver)) {

			return Environment.getDefaultMyProxy();
		} else {
			return new MyProxy(myproxyserver, myproxyPort);
		}
	}

	/**
	 * Delegates (uploads) a {@link GSSCredential} to the myproxy server with
	 * the specified proxy_paramters. Use the prepareProxyParameters() method to
	 * actually prepare them.
	 * 
	 * @param myproxy
	 *            the myproxy server to upload the credential to (create with
	 *            new MyProxy("server", port) - port is usually 7512)
	 * @param credential
	 *            the credential you want to delegate to the server (this uses a
	 *            {@link GlobusCredential}) instead of a {@link GSSCredential}
	 * @param proxy_parameters
	 *            the parameters for the credential on the myproxy server. See
	 *            the prepareProxyParameters() method.
	 * @param myProxyPassphrase
	 *            the passphrase for the credentials on the myproxy server.
	 * @throws GSSException
	 *             if the credential can't be used (or destroyed after the
	 *             upload)
	 * @throws MyProxyException
	 *             if the delegation process fails
	 */
	public static void init(MyProxy myproxy, GlobusCredential credential,
			InitParams proxy_parameters, char[] myProxyPassphraseboolean)
					throws MyProxyException, GSSException {

		init(myproxy, credential, proxy_parameters, myProxyPassphraseboolean,
				false);

	}

	/**
	 * Delegates (uploads) a {@link GSSCredential} to the myproxy server with
	 * the specified proxy_paramters. Use the prepareProxyParameters() method to
	 * actually prepare them.
	 * 
	 * @param myproxy
	 *            the myproxy server to upload the credential to (create with
	 *            new MyProxy("server", port) - port is usually 7512)
	 * @param credential
	 *            the credential you want to delegate to the server (this uses a
	 *            {@link GlobusCredential}) instead of a {@link GSSCredential}
	 * @param proxy_parameters
	 *            the parameters for the credential on the myproxy server. See
	 *            the prepareProxyParameters() method.
	 * @param myProxyPassphrase
	 *            the passphrase for the credentials on the myproxy server.
	 * @param storeMyProxyCredsLocally
	 *            whether to store the MyPropxy details on local disk for later
	 *            re-usage without having to re-upload again
	 * @throws GSSException
	 *             if the credential can't be used (or destroyed after the
	 *             upload)
	 * @throws MyProxyException
	 *             if the delegation process fails
	 */
	public static void init(MyProxy myproxy, GlobusCredential credential,
			InitParams proxy_parameters, char[] myProxyPassphrase,
			boolean storeMyProxyCredsLocally)
					throws GSSException, MyProxyException {

		GSSCredential newCredential = null;

		newCredential = new GlobusGSSCredentialImpl(credential,
				GSSCredential.INITIATE_AND_ACCEPT);
		myLogger.debug("Created gss_credentials.");

		// I don't use the InitParams from the method signature for
		// username/password because it uses a String for the passphrase instead
		// of char[]
		proxy_parameters.setPassphrase(new String(myProxyPassphrase));
		// Arrays.fill(myProxyPassphrase, 'x');

		myproxy.put(newCredential, proxy_parameters);
		myLogger.debug("Put myproxy credentials on server.");

		// very important to dispose the long-live credential after storage!
		newCredential.dispose();
		myLogger.debug("Disposed gss_credentials.");

		if (storeMyProxyCredsLocally) {
			storeMyProxyDetailsLocally(proxy_parameters.getUserName(),
					myProxyPassphrase);
		}

	}

	/**
	 * Delegates (uploads) a {@link GSSCredential} to the myproxy server with
	 * the specified proxy_paramters. Use the prepareProxyParameters() method to
	 * actually prepare them.
	 * 
	 * @param myproxy
	 *            the myproxy server to upload the credential to (create with
	 *            new MyProxy("server", port) - port is usually 7512)
	 * @param credential
	 *            the credential you want to delegate to the server
	 * @param proxy_parameters
	 *            the parameters for the credential on the myproxy server. See
	 *            the prepareProxyParameters() method.
	 * @param myProxyPassphrase
	 *            the passphrase for the credentials on the myproxy server.
	 * @throws GSSException
	 *             if the credential can't be used (or destroyed after the
	 *             upload)
	 * @throws MyProxyException
	 *             if the delegation process fails
	 */
	public static void init(MyProxy myproxy, GSSCredential credential,
			InitParams proxy_parameters, char[] myProxyPassphrase)
					throws GSSException, MyProxyException {

		init(myproxy, CredentialHelpers.unwrapGlobusCredential(credential),
				proxy_parameters, myProxyPassphrase, false);
	}

	/**
	 * Prepares the common parameters for a myproxy put operation. Paramaters
	 * marked as optional can be null.
	 * 
	 * @param username
	 *            the username for the proxy on the myproxy server
	 * @param proxyname
	 *            the credential name (so someone can have multiple proxies
	 *            under one username) for the proxy. (Optional)
	 * @param renewer
	 *            who is allowed to renew the delegated credential (* for
	 *            anonymous renewal - this is also used if null)
	 * @param retriever
	 *            who is allowed to retrieve a delegated credential (* for
	 *            anonymous retrieval - this is also used if null)
	 * @param description
	 *            a description for the credential. (Optional)
	 * @param lifetime_in_seconds
	 *            the lifetime of a delegated credential. (if smaller 0 the
	 *            hardcoded default lifetime of 12 h will be used)
	 * @return the parameters wrapped in one object
	 * @throws MyProxyException
	 *             if a required field is missing
	 */
	public static InitParams prepareProxyParameters(String username,
			String proxyname, String renewer, String retriever,
			String description, int lifetime_in_seconds)
					throws MyProxyException {

		InitParams proxy_parameters = new InitParams();

		if ((username == null) || "".equals(username)) {
			throw new MyProxyException("No myproxy username specified.");
		} else {
			proxy_parameters.setUserName(username);
		}

		if ((proxyname != null) && !"".equals(proxyname)) {
			proxy_parameters.setCredentialName(proxyname);
		}

		if ((renewer == null) || "".equals(renewer)) {
			// means anonymous renewer
			renewer = "*";
		}
		proxy_parameters.setRenewer(renewer);

		if ((retriever == null) || "".equals(retriever)) {
			// means anonymous retriever
			retriever = "*";
		}
		proxy_parameters.setRetriever(retriever);

		if ((description != null) || !"".equals(description)) {
			proxy_parameters.setCredentialDescription(description);
		}

		if (lifetime_in_seconds <= 0) {
			lifetime_in_seconds = PROXY_LIFETIME_DEFAULT;
		}
		proxy_parameters.setLifetime(lifetime_in_seconds);

		return proxy_parameters;
	}

	public static void storeMyProxyDetailsLocally(String username, char[] password) {



	}

}
