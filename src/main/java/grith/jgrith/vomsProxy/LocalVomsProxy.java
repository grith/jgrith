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

package grith.jgrith.vomsProxy;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.CredentialHelpers;
import grith.jgrith.plainProxy.LocalProxy;
import grith.jgrith.voms.VO;

import java.io.File;
import java.io.IOException;

import org.globus.common.CoGProperties;
import org.ietf.jgss.GSSCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LocalVomsProxy {

	static final Logger myLogger = LoggerFactory.getLogger(LocalProxy.class.getName());

	// this is the default apacgrid voms server
	public static final VO APACGRID_VO = new VO("APACGrid",
			"vomrs.apac.edu.au", 15001,
			"/C=AU/O=APACGrid/OU=APAC/CN=vomrs.apac.edu.au");

	// set this to whatever voms server you are using
	public static final VO DEFAULT_VO = APACGRID_VO;

	public static void main(String[] args) {

		char[] passphrase = "xxx".toCharArray();

		File proxyFile = new File(CoGProperties.getDefault().getProxyFile());
		proxyFile.delete();

		// LocalProxy.gridProxyInit(passphrase);
		try {
			LocalVomsProxy.vomsProxyInit("/APACGrid/NGAdmin", passphrase, 12);
		} catch (IOException e) {
			myLogger.error(e.getLocalizedMessage());
		} catch (Exception e) {
			myLogger.error(e.getLocalizedMessage());
		}

	}

	public static void vomsProxyDestroy() {
		LocalProxy.gridProxyDestroy();
	}

	/**
	 * Creates a voms proxy for the default VO specified above and writes it to
	 * disk.
	 * 
	 * @param group
	 *            the group you want to have the proxy for (example:
	 *            /APACGrid/NGAdmin)
	 * @param passphrase
	 *            the passphrase of your local private key
	 * @param lifetime_in_hours
	 *            how long the proxy should be valid
	 * @throws Exception
	 *             if another error occured
	 * @throws IOException
	 *             if the proxy could not be saved to disk
	 */
	public static void vomsProxyInit(String group, char[] passphrase,
			int lifetime_in_hours) throws IOException, Exception {
		vomsProxyInit(DEFAULT_VO, group, passphrase, lifetime_in_hours);
	}

	// public static ArrayList<String> vomsProxyInfo(){
	//
	// }

	/**
	 * This one creates a voms proxy with the requested vo information in it and
	 * saves it to the default globus location.
	 * 
	 * @param vo
	 *            the vo you want to have the proxy for
	 * @param group
	 *            the group you want to have the proxy for (example:
	 *            /APACGrid/NGAdmin)
	 * @param passphrase
	 *            the passphrase of your local private key
	 * @param lifetime_in_hours
	 *            how long the proxy should be valid
	 * @throws IOException
	 *             if the proxy could not be saved to disk
	 * @throws Exception
	 *             if another error occured
	 */
	public static void vomsProxyInit(VO vo, String group, char[] passphrase,
			int lifetime_in_hours) throws CredentialException {

		GSSCredential credential = VomsProxy.init(vo, group, passphrase,
				lifetime_in_hours);
		// get the default location of the grid-proxy file
		File proxyFile = new File(CoGProperties.getDefault().getProxyFile());
		try {
			// write the proxy to disk
			CredentialHelpers.writeToDisk(credential, proxyFile);
		} catch (CredentialException e) {
			// could not write proxy to disk
			myLogger.error("Could not write voms proxy to disk: "
					+ e.getMessage());
			throw e;
		}
	}

}
