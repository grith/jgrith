package grith.jgrith;

import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.myProxy.MyProxy_light;

import java.util.Arrays;

import org.apache.commons.lang.StringUtils;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;

public class MyProxyCredential extends Credential {
	
	private GSSCredential cred = null;
	
	private String myProxyHostOrig = DEFAULT_MYPROXY_SERVER;
	private int myProxyPortOrig = DEFAULT_MYPROXY_PORT;
	
	private String myProxyUsernameOrig = null;
	private char[] myProxyPasswordOrig = null;

	private final int myproxyLifetimeInSeconds;
	
	@Override
	public char[] getMyProxyPassword() {
		return myProxyPasswordOrig;
	}

	@Override
	public int getMyProxyPort() {
		return myProxyPortOrig;
	}
	
	@Override
	public String getMyProxyUsername() {
		return  myProxyUsernameOrig;
	}
	
	@Override
	public String getMyProxyServer() {
		return myProxyHostOrig;
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
	 * @throws CredentialException
	 *             if no valid proxy could be retrieved from MyProxy
	 */
	public MyProxyCredential(String myProxyUsername, char[] myProxyPassword,
			String myproxyHost, int myproxyPort, int lifetimeInSeconds)
					throws CredentialException {

		this.myProxyUsernameOrig = myProxyUsername;
		this.myProxyPasswordOrig = myProxyPassword;

		this.myproxyLifetimeInSeconds = lifetimeInSeconds;
		if (StringUtils.isBlank(myproxyHost)) {
			this.myProxyHostOrig = GridEnvironment.getDefaultMyProxyServer();
		} else {
			this.myProxyHostOrig = myproxyHost;
		}
		if (myproxyPort <= 0) {
			this.myProxyPortOrig = GridEnvironment.getDefaultMyProxyPort();
		} else {
			this.myProxyPortOrig = myproxyPort;
		}

		addProperty(PROPERTY.LoginType, LoginType.MYPROXY);
		addProperty(PROPERTY.MyProxyUsername, myProxyUsername);
		addProperty(PROPERTY.MyProxyPassword, new String(myProxyPassword));
		addProperty(PROPERTY.MyProxyHost, myproxyHost);
		addProperty(PROPERTY.MyProxyPort, myproxyPort);

	}
	
	/**
	 * The underlying GSSCredential.
	 * 
	 * @return the credential
	 * @throws CredentialException
	 *             if the credential can't be retrieved from MyProxy or the
	 *             lifetime of the credential is shorter than configured in
	 *             {@link #MIN_REMAINING_LIFETIME}.
	 */
	public GSSCredential getCredential() throws CredentialException {

		if ( this.cred == null ) {
			// means, get it from myproxy
			try {
				cred = MyProxy_light.getDelegation(myProxyHostOrig, myProxyPortOrig,
						myProxyUsernameOrig, myProxyPasswordOrig,
						myproxyLifetimeInSeconds);
			} catch (MyProxyException e) {
				throw new CredentialException(
						"Can't retrieve credential from MyProxy", e);
			}

		}

		return cred;
	}
	
	@Override
	public boolean isUploaded() {
		return true;
	}
	
	@Override
	public void destroyCredential() {
		myLogger.debug("Destrying original proxy from host: "
				+ myProxyHostOrig);
		try {
			MyProxy mp = new MyProxy(myProxyHostOrig, myProxyPortOrig);
			mp.destroy(getCredential(), myProxyUsernameOrig, new String(
					myProxyPasswordOrig));
		} catch (MyProxyException e) {
			myLogger.error("Can't destroy myproxy credential.", e);
		}
		
		Arrays.fill(myProxyPasswordOrig, 'x');
		
		
	}


}
