package grith.jgrith;

import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.utils.HttpProxyManager;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.log4j.Logger;
import org.globus.gsi.gssapi.auth.AuthorizationException;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyServerAuthorization;
import org.ietf.jgss.GSSContext;


public class Environment {

	static final Logger myLogger = Logger.getLogger(HttpProxyManager.class
			.getName());

	private static MyProxy myproxy = null;

	public static MyProxy getDefaultMyProxy() {

		myLogger.debug("Using default myproxy...");

		if (myproxy == null) {

			int port = GridEnvironment.getDefaultMyProxyPort();
			String server = GridEnvironment.getDefaultMyProxyServer();
			myLogger.debug("Creating default MyProxy object: " + server + " / "
					+ port);

			try {
				server = InetAddress.getByName(server).getHostAddress();
			} catch (final UnknownHostException e1) {
				e1.printStackTrace();
			}

			myproxy = new MyProxy(server, port);

			myproxy.setAuthorization(new MyProxyServerAuthorization() {
				@Override
				public void authorize(GSSContext context, String host)
						throws AuthorizationException {
					myLogger.debug("actual host: " + host);
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