package org.vpac.security.light.control;

import java.net.URL;
import java.net.URLClassLoader;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GlobusCredentialException;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.vpac.security.light.CredentialHelpers;
import org.vpac.security.light.Environment;
import org.vpac.security.light.certificate.CertificateHelper;
import org.vpac.security.light.myProxy.MyProxy_light;
import org.vpac.security.light.plainProxy.LocalProxy;
import org.vpac.security.light.plainProxy.PlainProxy;
import org.vpac.security.light.voms.VO;
import org.vpac.security.light.vomsProxy.VomsProxy;

import com.Ostermiller.util.RandPass;

/**
 * This class provides one-stop methods to create/upload a proxy to a MyProxy
 * server.
 * 
 * @author Markus Binsteiner
 * 
 */
public class DirectMyProxyUpload {

	/**
	 * Call this method if you want to upload a proxy directly to a MyProxy
	 * server. If you don't specify a MyProxy username the dn of the certificate
	 * is used. If you don't specify a MyProxy password a random one is created.
	 * There is a lot that can go wrong in this process so be sure to catch a
	 * {@link RuntimeException} if you call this method.
	 * 
	 * @param privateKeyPassphrase
	 *            the passphrase of the local private key of the user (in
	 *            $HOME/.globus/userkey.pem) or null if there is already a local
	 *            proxy on the machine
	 * @param myProxyServer
	 *            the hostname of the MyProxy server
	 * @param myProxyPort
	 *            the port of the MyProxy server
	 * @param myProxyUsername
	 *            the username of the proxy to create or null (the dn of the
	 *            credential is used in this case)
	 * @param myProxyPassphrase
	 *            the passphrase to secure the proxy on the MyProxy server or
	 *            null (a random passphrase is created in that case)
	 * @param proxyname
	 *            the name of the proxy on the MyProxy server (optional, use
	 *            null if you don't want to specify one)
	 * @param renewer
	 *            the renewer policy (optional, use "*" or null for anonymous)
	 * @param retriever
	 *            the retriever policy (optional, use "*" or null for anonymous)
	 * @param description
	 *            the description of the proxy (optional)
	 * @param lifetime_in_seconds
	 *            the lifetime in seconds
	 * @return a Map which contains the MyProxy username as key and the password
	 *         as value
	 */
	public static Map<String, char[]> init(char[] privateKeyPassphrase,
			String myProxyServer, int myProxyPort, String myProxyUsername,
			char[] myProxyPassphrase, String proxyname, String renewer,
			String retriever, String description, int lifetime_in_seconds) {

		GSSCredential proxy = null;

		if (privateKeyPassphrase == null) {
			// means, try to load existing local proxy from /tmp/x509up_u<uid>
			try {
				proxy = LocalProxy.loadGSSCredential();
			} catch (GlobusCredentialException e) {
				throw new RuntimeException("Could not load local proxy.", e);
			}
		} else {

			if (!CertificateHelper.globusCredentialsReady()) {
				throw new RuntimeException(
						"Cant' create proxy because either/both certificate & private key are missing.");
			}

			// create proxy from certificate / private key
			try {
				proxy = PlainProxy.init(privateKeyPassphrase,
						(lifetime_in_seconds / 3600) + 1);
			} catch (Exception e1) {
				throw new RuntimeException(
						"Could not create proxy from local certificate & private key: "
								+ e1.getMessage());
			}
			Arrays.fill(privateKeyPassphrase, 'x');
		}

		return init(proxy, myProxyServer, myProxyPort, myProxyUsername,
				myProxyPassphrase, proxyname, renewer, retriever, description,
				lifetime_in_seconds);
	}

	public static Map<String, char[]> init(GlobusCredential proxy,
			String myProxyServer, int myProxyPort, String myProxyUsername,
			char[] myProxyPassphrase, String proxyname, String renewer,
			String retriever, String description, int lifetime_in_seconds) {

		GSSCredential cred = CredentialHelpers.wrapGlobusCredential(proxy);
		return init(cred, myProxyServer, myProxyPort, myProxyUsername,
				myProxyPassphrase, proxyname, renewer, retriever, description,
				lifetime_in_seconds);

	}

	/**
	 * Call this method if you want to upload a proxy directly to a MyProxy
	 * server. If you don't specify a MyProxy username the dn of the certificate
	 * is used. If you don't specify a MyProxy password a random one is created.
	 * There is a lot that can go wrong in this process so be sure to catch a
	 * {@link RuntimeException} if you call this method.
	 * 
	 * @param proxy
	 *            the credential
	 * @param myProxyServer
	 *            the hostname of the MyProxy server
	 * @param myProxyPort
	 *            the port of the MyProxy server
	 * @param myProxyUsername
	 *            the username of the proxy to create or null (the dn of the
	 *            credential is used in this case)
	 * @param myProxyPassphrase
	 *            the passphrase to secure the proxy on the MyProxy server or
	 *            null (a random passphrase is created in that case)
	 * @param proxyname
	 *            the name of the proxy on the MyProxy server (optional, use
	 *            null if you don't want to specify one)
	 * @param renewer
	 *            the renewer policy (optional, use "*" or null for anonymous)
	 * @param retriever
	 *            the retriever policy (optional, use "*" or null for anonymous)
	 * @param description
	 *            the description of the proxy (optional)
	 * @param lifetime_in_seconds
	 *            the lifetime in seconds
	 * @return a Map which contains the MyProxy username as key and the password
	 *         as value
	 */
	public static Map<String, char[]> init(GSSCredential proxy,
			String myProxyServer, int myProxyPort, String myProxyUsername,
			char[] myProxyPassphrase, String proxyname, String renewer,
			String retriever, String description, int lifetime_in_seconds) {

		return init(proxy, myProxyServer, myProxyPort, myProxyUsername,
				myProxyPassphrase, proxyname, renewer, retriever, description,
				lifetime_in_seconds, true);

	}

	/**
	 * Call this method if you want to upload a proxy directly to a MyProxy
	 * server. If you don't specify a MyProxy username the dn of the certificate
	 * is used. If you don't specify a MyProxy password a random one is created.
	 * There is a lot that can go wrong in this process so be sure to catch a
	 * {@link RuntimeException} if you call this method.
	 * 
	 * @param proxy
	 *            the credential
	 * @param myProxyServer
	 *            the hostname of the MyProxy server
	 * @param myProxyPort
	 *            the port of the MyProxy server
	 * @param myProxyUsername
	 *            the username of the proxy to create or null (the dn of the
	 *            credential is used in this case)
	 * @param myProxyPassphrase
	 *            the passphrase to secure the proxy on the MyProxy server or
	 *            null (a random passphrase is created in that case)
	 * @param proxyname
	 *            the name of the proxy on the MyProxy server (optional, use
	 *            null if you don't want to specify one)
	 * @param renewer
	 *            the renewer policy (optional, use "*" or null for anonymous)
	 * @param retriever
	 *            the retriever policy (optional, use "*" or null for anonymous)
	 * @param description
	 *            the description of the proxy (optional)
	 * @param lifetime_in_seconds
	 *            the lifetime in seconds
	 * @param createUniqueMyProxyUsername
	 *            if you set this to true a timestamp will be appended to your
	 *            myproxy username
	 * @return a Map which contains the MyProxy username as key and the password
	 *         as value
	 */
	public static Map<String, char[]> init(GSSCredential proxy,
			String myProxyServer, int myProxyPort, String myProxyUsername,
			char[] myProxyPassphrase, String proxyname, String renewer,
			String retriever, String description, int lifetime_in_seconds,
			boolean createUniqueMyProxyUsername) {

		String username = myProxyUsername;
		if (StringUtils.isBlank(username)) {
			try {
				if (createUniqueMyProxyUsername) {
					username = proxy.getName().toString() + "_"
							+ new Long(new Date().getTime()).toString();
				} else {
					username = proxy.getName().toString();
				}
			} catch (GSSException e) {
				throw new RuntimeException(
						"Could not read created temporary proxy: "
								+ e.getMessage());
			}
		} else {
			if (createUniqueMyProxyUsername) {
				username = username + "_"
						+ new Long(new Date().getTime()).toString();
			}
		}

		if ((myProxyPassphrase == null) || (myProxyPassphrase.length == 0)) {
			myProxyPassphrase = new RandPass().getPassChars(10);
		}

		InitParams params = null;
		try {
			params = MyProxy_light.prepareProxyParameters(username, proxyname,
					renewer, retriever, description, lifetime_in_seconds);
		} catch (MyProxyException e) {
			throw new RuntimeException("Couldn not prepare proxy parameters: "
					+ e.getMessage());
		}

		MyProxy myproxy = new MyProxy(myProxyServer, myProxyPort);

		try {
			MyProxy_light.init(myproxy, proxy, params, myProxyPassphrase);
		} catch (Exception e) {
			throw new RuntimeException(
					"Could not upload proxy credential to the MyProxy server: "
							+ e.getMessage());
		}

		// contains myproxy username & password
		Map<String, char[]> result = new HashMap<String, char[]>();
		result.put(username, myProxyPassphrase);

		return result;
	}

	public static void main(String[] args) {

		StringBuffer classpath = new StringBuffer();
		ClassLoader applicationClassLoader = classpath.getClass()
				.getClassLoader();
		if (applicationClassLoader == null) {
			applicationClassLoader = ClassLoader.getSystemClassLoader();
		}
		URL[] urls = ((URLClassLoader) applicationClassLoader).getURLs();
		for (URL url : urls) {
			classpath.append(url.getFile()).append("\r\n");
		}

		System.out.println("Classpath: " + classpath.toString());

		VO vo = new VO("APACGrid", "vomrs.apac.edu.au", 15001,
				"/C=AU/O=APACGrid/OU=APAC/CN=vomrs.apac.edu.au");
		System.out.println("VO created");
		VomsProxy vomsProxy = null;
		try {
			vomsProxy = new VomsProxy(vo, "/APACGrid/NGAdmin",
					"xxxx".toCharArray(), 100000);
			System.out.println("Voms proxy created.");
		} catch (Exception e) {
			// that didn't work, did it?
			System.out.println("Couldn't create voms proxy: "
					+ e.getLocalizedMessage() + ". Exiting...");
			System.exit(1);
		}

		GSSCredential gssVomsProxy = CredentialHelpers
				.wrapGlobusCredential(vomsProxy.getVomsProxyCredential());
		System.out.println("Wrapped proxy in GSSCredential.");
		init(gssVomsProxy, Environment.getDefaultMyProxy().getHost(),
				Environment.getDefaultMyProxy().getPort(), "markus_voms",
				"myProxyPassword".toCharArray(), null, null, null, null, 500);
		System.out.println("Uploaded proxy to MyProxy server.");
	}

}
