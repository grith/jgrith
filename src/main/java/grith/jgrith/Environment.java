package grith.jgrith;

import grisu.jcommons.configuration.CommonGridProperties;
import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.dependencies.BouncyCastleTool;
import grisu.jcommons.utils.DefaultGridSecurityProvider;
import grisu.jcommons.utils.EnvironmentVariableHelpers;
import grisu.jcommons.utils.HttpProxyManager;
import grisu.jcommons.utils.JythonHelpers;
import grisu.jcommons.utils.UncaughtExceptionHandler;
import grith.jgrith.utils.CertificateFiles;

import java.io.File;
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
	
	public static volatile boolean environmentInitialized = false;


	
	public static synchronized boolean initEnvironment() {

		if (!environmentInitialized) {
			
			EnvironmentVariableHelpers.loadEnvironmentVariablesToSystemProperties();

			HttpProxyManager.setDefaultHttpProxy();

			// make sure tmp dir exists
			String tmpdir = System.getProperty("java.io.tmpdir");
			if (tmpdir.startsWith("~")) {
				tmpdir = tmpdir.replaceFirst("~",
						System.getProperty("user.home"));
				System.setProperty("java.io.tmpdir", tmpdir);
			}
			File tmp = new File(tmpdir);
			if (!tmp.exists()) {
				myLogger.debug("Creating tmpdir: {}", tmpdir);
				tmp.mkdirs();
				if (!tmp.exists()) {
					myLogger.error("Could not create tmp dir {}.", tmpdir);
				}
			}

			java.util.logging.LogManager.getLogManager().reset();
			// LoggerFactory.getLogger("root").setLevel(Level.OFF);

			JythonHelpers.setJythonCachedir();

			final String debug = CommonGridProperties
					.getDefault()
					.getGridProperty(
							CommonGridProperties.Property.DEBUG_UNCAUGHT_EXCEPTIONS);

			if ("true".equalsIgnoreCase(debug)) {
				Thread.setDefaultUncaughtExceptionHandler(new UncaughtExceptionHandler());
			}

			java.security.Security
					.addProvider(new DefaultGridSecurityProvider());

			java.security.Security
					.setProperty("ssl.TrustManagerFactory.algorithm",
							"TrustAllCertificates");

			try {
				BouncyCastleTool.initBouncyCastle();
			} catch (final Exception e) {
				myLogger.error(e.getLocalizedMessage(), e);
			}

			environmentInitialized = true;

			try {
				CertificateFiles.copyCACerts(false);
			} catch (Exception e) {
				myLogger.error("Problem copying root certificates.", e);
			}

			return true;
		} else {
			return false;
		}

	}

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
