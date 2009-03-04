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

import org.apache.log4j.Logger;
import org.globus.gsi.GlobusCredential;
import org.globus.tools.proxy.DefaultGridProxyModel;
import org.ietf.jgss.GSSCredential;
import org.vpac.security.light.CredentialHelpers;

public class PlainProxy {
	
	static final Logger myLogger = Logger.getLogger(PlainProxy.class.getName());
	
	/**
	 * Creates a {@link GSSCredential} using all the (cog-) defaults like cert in $HOME/.globus/usercert.pem...
	 * 
	 * @param passphrase the passphrase of your private key
	 * @param lifetime_in_hours the lifetime of the proxy
	 * @return the proxy 
	 * @throws Exception if something has gone wrong
	 */
	public static GSSCredential init(char[] passphrase, int lifetime_in_hours) throws Exception {
		
		// get the cog default model for a proxy
		DefaultGridProxyModel model =  new DefaultGridProxyModel();
		// set the lifetime of the proxy
		model.getProperties().setProxyLifeTime(lifetime_in_hours);
		
		GlobusCredential globusCred = null;
		
		try {
			// do the actual grid-proxy-init. the model knows about the default 
			// private key and certificate location in $HOME/.globus
			globusCred = model.createProxy(new String(passphrase));
		} catch (Exception e) {
			// hm. something's gone wrong. not good.
			myLogger.error("Could not create local grid proxy: "+e.getMessage());
			throw e;
		}
		
		return CredentialHelpers.wrapGlobusCredential(globusCred);
		
	}

}
