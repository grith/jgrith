package org.vpac.security.light;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.log4j.Logger;
import org.globus.gsi.gssapi.auth.AuthorizationException;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyServerAuthorization;
import org.ietf.jgss.GSSContext;

import au.org.arcs.jcommons.constants.ArcsEnvironment;
import au.org.arcs.jcommons.utils.HttpProxyManager;

public class Environment {

	static final Logger myLogger = Logger.getLogger(HttpProxyManager.class
			.getName());

	private static MyProxy myproxy = null;

	public static MyProxy getDefaultMyProxy() {
		if (myproxy == null) {

			int port = ArcsEnvironment.getDefaultMyProxyPort();
			String server = ArcsEnvironment.getDefaultMyProxyServer();
			myLogger.debug("Creating default MyProxy object: " + server + " / "
					+ port);
			myproxy = new MyProxy(server, port);

			myproxy.setAuthorization(new MyProxyServerAuthorization() {
				@Override
				public void authorize(GSSContext context, String host)
						throws AuthorizationException {
					System.out.println("" + host);
					try {
						InetAddress addr = InetAddress.getByName(host);
						String hostname = addr.getHostName();
						if (!"myproxy.arcs.org.au".equals(hostname)
								&& !"myproxy2.arcs.org.au".equals(hostname)
								&& !"202.158.218.205".equals(hostname)) {
							throw new AuthorizationException(context
									.getDelegCred().getName().toString());
						}
					} catch (UnknownHostException ex) {
						throw new AuthorizationException("DNS lookup failed");
					} catch (org.ietf.jgss.GSSException ex) {
						throw new AuthorizationException("hmm ");
					}

				}
			});
		}
		return myproxy;
	}
}
