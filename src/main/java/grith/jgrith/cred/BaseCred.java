package grith.jgrith.cred;

import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.cred.AbstractCred.PROPERTY;
import grith.jgrith.myProxy.MyProxy_light;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.globus.common.CoGProperties;
import org.globus.myproxy.MyProxyException;
import org.globus.util.Util;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.Ostermiller.util.RandPass;
import com.google.common.collect.Maps;

public class BaseCred {

	static final Logger myLogger = LoggerFactory.getLogger(BaseCred.class
			.getName());

	public static final String DEFAULT_MYPROXY_FILE_EXTENSION = ".mp";

	public static final String DEFAULT_MYPROXY_FILE_LOCATION = CoGProperties
			.getDefault().getProxyFile() + DEFAULT_MYPROXY_FILE_EXTENSION;

	public static final int DEFAULT_MIN_LIFETIME_IN_SECONDS = 1200;

	public static final String CHILD_KEY = "group";

	public static String extractMyProxyServerFromUsername(String un) {

		int index = un.lastIndexOf('@');
		if (index <= 0) {
			return "";
		}

		return un.substring(index + 1);
	}

	public static String extractUsernameFromUsername(String un) {

		int index = un.lastIndexOf('@');
		if (index <= 0) {
			return un;
		}

		return un.substring(0, index);
	}

	private String myProxyUsername;

	private char[] myProxyPassword;
	private String myProxyHost;

	private int myProxyPort = 7512;
	protected String localMPPath = DEFAULT_MYPROXY_FILE_LOCATION;

	private int minLifetimeInSecondsBeforeReDownload = DEFAULT_MIN_LIFETIME_IN_SECONDS;

	private GSSCredential cachedMyProxyCredential = null;

	public BaseCred() {
		this(null, null, null, -1);
	}

	public BaseCred(Map<PROPERTY, Object> config) {

		initMyProxy(config);
	}

	public BaseCred(String un, char[] pw) {
		this(un, pw, null, -1);
	}

	public BaseCred(String un, char[] pw, String host) {
		this(un, pw, host, -1);
	}

	public BaseCred(String un, char[] pw, String host, Integer port) {

		if (StringUtils.isNotBlank(un)) {

			Map<PROPERTY, Object> config = Maps.newHashMap();
			config.put(PROPERTY.MyProxyUsername, un);
			config.put(PROPERTY.MyProxyPassword, pw);
			config.put(PROPERTY.MyProxyHost, host);
			config.put(PROPERTY.MyProxyPort, port);

			initMyProxy(config);
		}

	}

	public void destroyMyProxy() {

		if (StringUtils.isNotBlank(localMPPath)) {
			if (new File(localMPPath).exists()) {
				myLogger.debug("Deleting proxy file " + localMPPath);
				Util.destroy(localMPPath);
			}
		}

		if (cachedMyProxyCredential != null) {
			try {
				cachedMyProxyCredential.dispose();
			} catch (Exception e) {
				myLogger.debug("Error when disposing cached gss credential.", e);
			}
		}

		Arrays.fill(getMyProxyPassword(), 'x');

	}

	public GSSCredential getGSSCredentialMyProxy() {

		try {
			if ((cachedMyProxyCredential == null)
					|| (cachedMyProxyCredential.getRemainingLifetime() < minLifetimeInSecondsBeforeReDownload)) {

				try {
					cachedMyProxyCredential = MyProxy_light.getDelegation(
							getMyProxyHost(), getMyProxyPort(),
							getMyProxyUsername(), getMyProxyPassword(), 0);
				} catch (MyProxyException e) {
					throw new CredentialException(
							"Could not retrieve myproxy credential '"
									+ getMyProxyUsername() + "' (from: '"
									+ getMyProxyHost() + "')", e);
				}
			}
		} catch (GSSException e) {
			throw new CredentialException(
					"Could not get lifetime of credential.", e);
		}
		return cachedMyProxyCredential;

	}

	public String getMyProxyHost() {
		if (StringUtils.isBlank(myProxyHost)) {
			return GridEnvironment.getDefaultMyProxyServer();
		}
		return myProxyHost;
	}

	public char[] getMyProxyPassword() {
		if ((this.myProxyPassword == null)
				|| (this.myProxyPassword.length == 0)) {
			this.myProxyPassword = new RandPass().getPassChars(10);
		}
		return myProxyPassword;
	}

	public String getMyProxyPath() {

		if (StringUtils.isNotBlank(this.localMPPath)
				&& new File(this.localMPPath).exists()) {
			return this.localMPPath;
		}
		return null;
	}

	public int getMyProxyPort() {
		if (myProxyPort <= 0) {
			return GridEnvironment.getDefaultMyProxyPort();
		}
		return myProxyPort;
	}

	public String getMyProxyUsername() {
		if (StringUtils.isBlank(myProxyUsername)) {
			this.myProxyUsername = UUID.randomUUID().toString();
		}
		return myProxyUsername;
	}

	public int getRemainingLifetimeMyProxy() {
		try {
			return getGSSCredentialMyProxy().getRemainingLifetime();
		} catch (GSSException e) {
			throw new CredentialException("Can't get remaining lifetime.", e);
		} catch (CredentialException ce) {
			myLogger.debug("Can't get base gsscredential.", ce);
			return 0;
		}
	}

	protected void initMyProxy(Map<PROPERTY, Object> config) {

		String un = (String) config.get(PROPERTY.MyProxyUsername);
		char[] pw = (char[]) config.get(PROPERTY.MyProxyPassword);
		String host = (String) config.get(PROPERTY.MyProxyHost);
		int port = -1;
		try {
			port = (Integer) config.get(PROPERTY.MyProxyPort);
		} catch (Exception e) {
			port = GridEnvironment.getDefaultMyProxyPort();
		}

		if (StringUtils.isBlank(un)) {
			this.myProxyUsername = UUID.randomUUID().toString();
		} else {
			String temp = extractMyProxyServerFromUsername(un);
			if (StringUtils.isBlank(temp)) {
				this.myProxyUsername = un;
				this.myProxyHost = host;
			} else {
				this.myProxyUsername = extractUsernameFromUsername(un);
				this.myProxyHost = temp;
			}
		}

		if (StringUtils.isBlank(this.myProxyHost)) {
			this.myProxyHost = GridEnvironment.getDefaultMyProxyServer();
		}

		if ((pw == null) || (pw.length == 0)) {
			this.myProxyPassword = new RandPass().getPassChars(10);

		} else {
			this.myProxyPassword = pw;
		}

		if (port <= 0) {
			port = GridEnvironment.getDefaultMyProxyPort();
		} else {
			this.myProxyPort = port;
		}
	}

	protected void invalidateCachedCredential() {
		this.cachedMyProxyCredential = null;
	}


	public boolean isValidMyProxy() {
		return (getRemainingLifetimeMyProxy() > 0);
	}

	public void saveMyProxy() {
		saveMyProxy(null);
	}

	/**
	 * Saves the metadata file for this myproxy (contains host, username,
	 * password,...).
	 * 
	 * Only works if proxy is already stored in the path.
	 * 
	 * @param path
	 *            the path for the proxy (.mp) will be appended
	 */
	public void saveMyProxy(String path) {
		
		if (StringUtils.isBlank(path)) {
			path = DEFAULT_MYPROXY_FILE_LOCATION;
		}

		File proxyFile = new File(path);
		if (!proxyFile.exists()) {
			myLogger.debug("No proxy file exists on {}", path);
			throw new CredentialException(
					"Can't save myproxy metadata, proxy file " + path
							+ " does not exist.");
		}

		this.localMPPath = path + DEFAULT_MYPROXY_FILE_EXTENSION;

		File mpProxyFile = new File(localMPPath);
		Properties prop = new Properties();

		if (mpProxyFile.exists()) {
			myLogger.debug(
					"MyProxy proxy file already exists, deleting it ({})",
					localMPPath);
		}

		prop.put(PROPERTY.MyProxyUsername.toString(), getMyProxyUsername());
		prop.put(PROPERTY.MyProxyPassword.toString(), new String(
				getMyProxyPassword()));
		prop.put(PROPERTY.MyProxyHost.toString(), getMyProxyHost());
		prop.put(PROPERTY.MyProxyPort.toString(),
				Integer.toString(getMyProxyPort()));

		try {
			prop.store(new FileOutputStream(mpProxyFile), null);
			Util.setFilePermissions(mpProxyFile.getAbsolutePath(), 600);
		} catch (Exception e) {
			throw new CredentialException("Can't store credential metadata.", e);
		}
	}

	public void setMyProxyHost(String mph) {
		this.myProxyHost = mph;
	}

	public void setMyProxyPassword(char[] pw) {
		this.myProxyPassword = pw;
	}

	public void setMyProxyPort(int port) {
		this.myProxyPort = port;
	}

	public void setMyProxyUsername(String username) {
		if (StringUtils.isBlank(username)) {
			this.myProxyUsername = null;
			return;
		}
		String tmp = extractMyProxyServerFromUsername(username);
		if (StringUtils.isNotBlank(tmp)) {
			this.myProxyHost = tmp;
			this.myProxyUsername = extractUsernameFromUsername(username);
		} else {
			this.myProxyUsername = username;
		}
	}


	@Override
	public String toString() {
		if (StringUtils.equals(myProxyHost,
				GridEnvironment.getDefaultMyProxyServer())) {
			return myProxyUsername;
		} else {
			return myProxyUsername + '@' + myProxyHost;
		}
	}

}
