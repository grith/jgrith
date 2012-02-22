package grith.jgrith.credential;

import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.myProxy.MyProxy_light;

import java.util.Arrays;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;

public class MyProxyCredential extends Credential {

	// private String myProxyHostOrig = DEFAULT_MYPROXY_SERVER;
	// private int myProxyPortOrig = DEFAULT_MYPROXY_PORT;
	//
	// private String myProxyUsernameOrig = null;
	// private char[] myProxyPasswordOrig = null;

	public MyProxyCredential(Map<PROPERTY, Object> config) {
		super(config);
	}

	public MyProxyCredential(String un, char[] pw) {
		this(un, pw, -1);
	}

	public MyProxyCredential(String un, char[] pw, int lifetime_in_seconds) {
		this(un, pw, GridEnvironment.getDefaultMyProxyServer(), GridEnvironment
				.getDefaultMyProxyPort(), lifetime_in_seconds);
	}

	/**
	 * Creates a Credential object from MyProxy login information.
	 * 
	 * @param myProxyUsername
	 *            the MyProxy username
	 * @param myProxyPassword
	 *            the MyProxy password
	 * @param myproxyHost
	 *            the MyProxy host
	 * @param myproxyPort
	 *            the MyProxy port
	 * @param lifetimeInSeconds
	 *            the lifetime of the delegated proxy
	 * @param storePassphraseInMemory
	 *            whether to store the password provided here in memory in order
	 *            to be able to easily and automatically refresh it
	 * @throws CredentialException
	 *             if no valid proxy could be retrieved from MyProxy
	 */
	public MyProxyCredential(String myProxyUsername, char[] myProxyPassword,
			String myproxyHost, int myproxyPort, int lifetimeInSeconds)
					throws CredentialException {



		if (StringUtils.isBlank(myproxyHost)) {
			myproxyHost = GridEnvironment.getDefaultMyProxyServer();
		}

		if (myproxyPort <= 0) {
			myproxyPort = GridEnvironment.getDefaultMyProxyPort();
		}

		if (lifetimeInSeconds <= 0) {
			lifetimeInSeconds = DEFAULT_PROXY_LIFETIME_IN_HOURS * 3600;
		}

		addProperty(PROPERTY.LoginType, LoginType.MYPROXY);
		addProperty(PROPERTY.MyProxyUsername, myProxyUsername);
		addProperty(PROPERTY.MyProxyPassword, myProxyPassword);
		addProperty(PROPERTY.MyProxyHost, myproxyHost);
		addProperty(PROPERTY.MyProxyPort, myproxyPort);
		addProperty(PROPERTY.LifetimeInSeconds, lifetimeInSeconds);

	}

	@Override
	public Map<PROPERTY, Object> autorefreshConfig() {
		return null;
	}

	@Override
	public GSSCredential createGssCredential(Map<PROPERTY, Object> config)
			throws CredentialException {

		Object pw = config.get(PROPERTY.MyProxyPassword);

		String un = (String) config.get(PROPERTY.MyProxyUsername);
		String host = (String) config.get(PROPERTY.MyProxyHost);

		Integer port = (Integer) config.get(PROPERTY.MyProxyPort);


		return createGssCredential(un, (char[]) pw, host, port);
	}

	public GSSCredential createGssCredential(String myproxyUsername,
			char[] myproxyPassword, String myproxyhost, int myproxyPort)
					throws CredentialException {

		try {
			if (myproxyPassword == null) {
				myproxyPassword = (char[]) getProperty(PROPERTY.MyProxyPassword);
			}

			if (StringUtils.isBlank(myproxyUsername)) {
				myproxyUsername = (String) getProperty(PROPERTY.MyProxyUsername);
			}
			if (StringUtils.isBlank(myproxyhost)) {
				myproxyhost = (String) getProperty(PROPERTY.MyProxyHost);
			}
			if (myproxyPort <= 0) {
				myproxyPort = (Integer) getProperty(PROPERTY.MyProxyPort);
			}
			return MyProxy_light.getDelegation(myproxyhost, myproxyPort,
					myproxyUsername, myproxyPassword, getInitialLifetime());
		} catch (Exception e) {
			myLogger.error("Can't refresh myproxy credential.", e);
			throw new CredentialException("Can't retrieve MyProxy credential: "
					+ e.getLocalizedMessage(), e);
		}
	}



	@Override
	protected void destroyCredential() {
		myLogger.debug("Destrying original proxy from host: "
				+ getProperty(PROPERTY.MyProxyHost));
		try {
			MyProxy mp = new MyProxy(
					(String) getProperty(PROPERTY.MyProxyHost),
					(Integer) getProperty(PROPERTY.MyProxyPort));
			mp.destroy(getGSSCredential(), (String)getProperty(PROPERTY.MyProxyUsername), new String(
					(char[]) getProperty(PROPERTY.MyProxyPassword)));
		} catch (MyProxyException e) {
			myLogger.error("Can't destroy myproxy credential.", e);
		}

		Arrays.fill((char[]) getProperty(PROPERTY.MyProxyPassword), 'x');


	}



	@Override
	public char[] getMyProxyPassword() {
		return (char[]) getProperty(PROPERTY.MyProxyPassword);
	}

	@Override
	public int getMyProxyPort() {
		return (Integer) getProperty(PROPERTY.MyProxyPort);
	}

	@Override
	public String getMyProxyServer() {
		return (String) getProperty(PROPERTY.MyProxyHost);
	}

	@Override
	public String getMyProxyUsername() {
		return (String) getProperty(PROPERTY.MyProxyUsername);
	}

	@Override
	public boolean isAutoRenewable() {
		return true;
	}

	@Override
	public boolean isUploaded() {
		return true;
	}

	@Override
	protected void setGssCredential(GSSCredential cred) {
		// TODO upload?
	}

	@Override
	public synchronized void uploadMyProxy(String myProxyHostUp,
			int myProxyPortUp, boolean force) throws CredentialException {
		myLogger.debug("Not uploading this because it is a myproxy credential already...");
	}

}
