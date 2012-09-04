package grith.jgrith;

import grisu.jcommons.constants.GridEnvironment;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.globus.gsi.gssapi.auth.AuthorizationException;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyServerAuthorization;
import org.ietf.jgss.GSSContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Environment {

	static final Logger myLogger = LoggerFactory.getLogger(Environment.class
			.getName());

	private static MyProxy myproxy = null;

	public static MyProxy getARCSMyProxy() {

		myLogger.debug("Using default ARCS myproxy...");

		if (myproxy == null) {

			int port = 7512;
			String server = "myproxy.arcs.org.au";
			myLogger.debug("Creating default MyProxy object: " + server + " / "
					+ port);

			try {
				server = InetAddress.getByName(server).getHostAddress();
			} catch (final UnknownHostException e1) {
				myLogger.error(e1.getLocalizedMessage());
			}

			myproxy = new MyProxy(server, port);

			myproxy.setAuthorization(new MyProxyServerAuthorization() {
				@Override
				public void authorize(GSSContext context, String host)
						throws AuthorizationException {
					myLogger.debug("actual host: " + host);
					try {
						// TODO make this configurable?
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

	public static MyProxy getDefaultMyProxy() {
		MyProxy mp = new MyProxy(GridEnvironment.getDefaultMyProxyServer(),
				GridEnvironment.getDefaultMyProxyPort());
		return mp;
	}
}
