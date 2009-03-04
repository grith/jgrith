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

package org.vpac.security.light.myProxy;

import java.io.File;
import java.io.IOException;

import org.apache.log4j.Logger;
import org.globus.common.CoGProperties;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.vpac.security.light.CredentialHelpers;

/**
 * I called this class LocalMyProxy so that there is no confusion with the MyProxy class from the cog kit.
 * Its main purpose is to contact a myproxy server, get a delegated proxy and save that proxy to disk.
 * Also, this class has got hardcoded information about the APACGrid myproxy server in it...
 * 
 * @author Markus Binsteiner
 *
 */
public class LocalMyProxy {
	
	static final Logger myLogger = Logger.getLogger(LocalMyProxy.class.getName());

	/**
	 * The default myproxy server of the APACGrid.
	 */
	public static final MyProxy DEFAULT_MYPROXY_SERVER = new MyProxy("myproxy.arcs.org.au", 443);
	
	/**
	 * Equivalent to the commandline myproxy-get-delegation command for getting an anonymous proxy. It retrieves
	 * a proxy from the MyProxy server and writes it to disk (/tmp/x509up_uXXXX on linux)
	 * 
	 * @param myproxyServer the hostname of the myproxy server
	 * @param myproxyPort the port of the myproxy server (default is 443)
	 * @param username the username the user used when uploading the proxy
	 * @param passphrase the passphrase the user used when uploading the proxy
	 * @param lifetime_in_secs how long you want the proxy to be valid
	 * @return the proxy credential
	 * @throws MyProxyException if something did not work
	 * @throws GSSException if something is wrong with the retrieved proxy
	 * @throws IOException if the proxy can't be written to disk
	 */
	public static void getDelegationAndWriteToDisk(String myproxyServer, int myproxyPort, String username, char[] passphrase, int lifetime_in_secs) throws MyProxyException, IOException, GSSException{
		
		GSSCredential credential = MyProxy_light.getDelegation(myproxyServer, myproxyPort, username, passphrase, lifetime_in_secs);
		CredentialHelpers.writeToDisk(credential, new File(CoGProperties.getDefault().getProxyFile()));
	}
	
	/**
	 * Equivalent to the commandline myproxy-get-delegation command for getting an anonymous proxy. The proxy is retrieved 
	 * from the MyProxy server and written to disk. This uses default server which is
	 * hardcoded in this class ({@link LocalMyProxy.DEFAULT_MYPROXY_SERVER}).
	 * 
	 * @param username the username the user used when uploading the proxy
	 * @param passphrase the passphrase the user used when uploading the proxy
	 * @param lifetime_in_seconds how long you want the proxy to be valid
	 * @return the proxy credential
	 * @throws MyProxyException if something did not work
	 * @throws GSSException if something is wrong with the retrieved proxy
	 * @throws IOException if the proxy can't be written to disk
	 */
	public static void getDelegationAndWriteToDisk(String username, char[] passphrase, int lifetime_in_seconds) throws MyProxyException, IOException, GSSException {
		getDelegationAndWriteToDisk(DEFAULT_MYPROXY_SERVER.getHost(), DEFAULT_MYPROXY_SERVER.getPort(), username, passphrase, lifetime_in_seconds);
	}
	
	/**
	 * Equivalent to the commandline myproxy-get-delegation command for getting a non-anonymous proxy
	 * 
	 * @param myproxyServer the hostname of the myproxy server
	 * @param myproxyPort the port of the myproxy server (default is 443)
	 * @param credential the credential you want to use to authenticate against the MyProxy server
	 * @param username the username the user used when uploading the proxy
	 * @param passphrase the passphrase the user used when uploading the proxy
	 * @param lifetime_in_seconds how long you want the proxy to be valid
	 * @return the proxy credential
	 * @throws MyProxyException if something did not work
	 * @throws GSSException if something is wrong with the retrieved proxy
	 * @throws IOException if the proxy can't be written to disk
	 */
	public static void getDelegationAndWriteToDisk(String myproxyServer, int myproxyPort, GSSCredential credential, String username, char[] passphrase, int lifetime_in_seconds) throws MyProxyException, IOException, GSSException {

		GSSCredential new_credential = MyProxy_light.getDelegation(myproxyServer, myproxyPort, credential, username, passphrase, lifetime_in_seconds);
		CredentialHelpers.writeToDisk(new_credential, new File(CoGProperties.getDefault().getProxyFile()));
	}
	
	/**
	 * Equivalent to the commandline myproxy-get-delegation command for getting a non-anonymous proxy. The proxy is retrieved 
	 * from the MyProxy server and written to disk. This uses default server which is
	 * hardcoded in this class ({@link LocalMyProxy.DEFAULT_MYPROXY_SERVER}).
	 * 
	 * @param credential the credential you want to use to authenticate against the MyProxy server
	 * @param username the username the user used when uploading the proxy
	 * @param passphrase the passphrase the user used when uploading the proxy
	 * @param lifetime_in_seconds how long you want the proxy to be valid
	 * @return the proxy credential
	 * @throws MyProxyException if something did not work
	 * @throws GSSException if something is wrong with the retrieved proxy
	 * @throws IOException if the proxy can't be written to disk
	 */
	public static void getDelegationAndWriteToDisk(GSSCredential credential, String username, char[] passphrase, int lifetime_in_seconds) throws MyProxyException, IOException, GSSException {
		getDelegationAndWriteToDisk(DEFAULT_MYPROXY_SERVER.getHost(), DEFAULT_MYPROXY_SERVER.getPort(), credential, username, passphrase, lifetime_in_seconds);
	}
	
	

}
