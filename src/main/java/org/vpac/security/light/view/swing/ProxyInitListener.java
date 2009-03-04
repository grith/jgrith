package org.vpac.security.light.view.swing;

import org.globus.gsi.GlobusCredential;
import org.vpac.security.light.vomsProxy.VomsException;

public interface ProxyInitListener {
	
	public static final Integer PLAIN_PROXY_CREATED = 0;
	public static final Integer VOMS_PROXY_CREATED = 1;

	/**
	 * 
	 * @param newProxy the newly create proxy
	 */
	public void proxyCreated(GlobusCredential newProxy);

	public void proxyDestroyed();
	
}
