package grith.jgrith.control;

import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.utils.FileSystemHelpers;

import java.util.Arrays;

import org.apache.commons.lang.StringUtils;

import com.google.common.collect.ImmutableBiMap;
import com.google.common.collect.ImmutableMap;
/**
 * A class that holds all information that is needed to login to a Grisu web
 * service.
 * 
 * There has to be a proxy delegated to a MyProxy server, though.
 * 
 * @author Markus Binsteiner
 * 
 */
public class LoginParams {

	private String loginUrl;
	private String myProxyUsername = null;
	private char[] myProxyPassphrase = null;
	private String myProxyServer = null;
	private String myProxyPort = null;
	private String httpProxy = null;
	private int httpProxyPort = -1;
	private String httpProxyUsername = null;
	private char[] httpProxyPassphrase = null;

	private ImmutableBiMap<String, String> aliasMap = null;
	private ImmutableMap<String, String> myProxyMap = null;

	/**
	 * This one allows you to specify everything: myproxy server & port, http
	 * proxy server & port & username & password.
	 * 
	 * @param loginUrl
	 *            the url of the grisu backend to connect to
	 * @param myProxyUsername
	 *            your myproxy username
	 * @param myProxyPassphrase
	 *            your myproxy password
	 * @param myProxyServer
	 *            the myproxy server hostname
	 * @param myProxyPort
	 *            the myproxy server port
	 * @param httpProxy
	 *            the http proxy server hostname
	 * @param httpProxyPort
	 *            the http proxy server port
	 * @param httpProxyUsername
	 *            the http proxy server username
	 * @param httpProxyPassphrase
	 *            the http proxy server password
	 */
	public LoginParams(
			final String myProxyUsername, final char[] myProxyPassphrase,
			final String myProxyServer, final String myProxyPort,
			final String httpProxy, final int httpProxyPort,
			final String httpProxyUsername, final char[] httpProxyPassphrase) {
		setLoginUrl(loginUrl);
		this.myProxyUsername = myProxyUsername;
		this.myProxyPassphrase = myProxyPassphrase;
		this.myProxyServer = myProxyServer;
		this.myProxyPort = myProxyPort;
		this.httpProxy = httpProxy;
		this.httpProxyPort = httpProxyPort;
		this.httpProxyUsername = httpProxyUsername;
		this.httpProxyPassphrase = httpProxyPassphrase;
	}

	/**
	 * This one uses the default myproxy server & port. No http proxy is used.
	 * 
	 * @param loginUrl
	 *            the url of the grisu backend to connect to
	 * @param myProxyUsername
	 *            your myproxy username
	 * @param myProxyPassphrase
	 *            your myproxy password
	 */
	public LoginParams(final String url,
			final String myProxyUsername, final char[] myProxyPassphrase) {
		this(url, myProxyUsername, myProxyPassphrase, null, null);
	}

	/**
	 * This one allows you to specify the myproxy server & port to use. No http
	 * proxy is used.
	 * 
	 * @param loginUrl
	 *            the url of the grisu backend to connect to
	 * @param myProxyUsername
	 *            your myproxy username
	 * @param myProxyPassphrase
	 *            your myproxy password
	 * @param myProxyServer
	 *            the myproxy server to use
	 * @param myProxyPort
	 *            the port of the myproxy server
	 */
	public LoginParams(String url,
			final String myProxyUsername, final char[] myProxyPassphrase,
			final String myProxyServer, final String myProxyPort) {
		setLoginUrl(url);
		this.myProxyUsername = myProxyUsername;
		this.myProxyPassphrase = myProxyPassphrase;
		this.myProxyServer = myProxyServer;
		this.myProxyPort = myProxyPort;
	}

	/**
	 * This one allows you to specify the myproxy server & port as well as the
	 * http proxy server & port. No http proxy authentication.
	 * 
	 * @param loginUrl
	 *            the url of the grisu backend to connect to
	 * @param myProxyUsername
	 *            your myproxy username
	 * @param myProxyPassphrase
	 *            your myproxy password
	 * @param myProxyServer
	 *            the myproxy server hostname
	 * @param myProxyPort
	 *            the myproxy server port
	 * @param httpProxy
	 *            the http proxy server hostname
	 * @param httpProxyPort
	 *            the http proxy server port
	 */
	public LoginParams(String url,
			final String myProxyUsername, final char[] myProxyPassphrase,
			final String myProxyServer, final String myProxyPort,
			final String httpProxy, final int httpProxyPort) {
		setLoginUrl(url);
		this.myProxyUsername = myProxyUsername;
		this.myProxyPassphrase = myProxyPassphrase;
		this.myProxyServer = myProxyServer;
		this.myProxyPort = myProxyPort;
		this.httpProxy = httpProxy;
		this.httpProxyPort = httpProxyPort;
	}

	/**
	 * Clears the password for the http proxy server in memory. Not the myproxy
	 * one, though, since this is still needed after login.
	 */
	public final void clearPasswords() {
		// if ( this.myProxyPassphrase != null ) {
		// Arrays.fill(this.myProxyPassphrase, 'x');
		// }
		if (this.httpProxyPassphrase != null) {
			Arrays.fill(this.httpProxyPassphrase, 'x');
		}

	}

	/**
	 * Returns the http proxy server hostname.
	 * 
	 * @return the http proxy server hostname
	 */
	public final String getHttpProxy() {
		return httpProxy;
	}

	/**
	 * Returns the password for the http proxy server.
	 * 
	 * @return the http proxy server password
	 */
	public final char[] getHttpProxyPassphrase() {
		return httpProxyPassphrase;
	}

	/**
	 * Gets the http proxy server port.
	 * 
	 * @return the http proxy server port
	 */
	public final int getHttpProxyPort() {
		return httpProxyPort;
	}

	/**
	 * Returns the username for the http proxy server.
	 * 
	 * @return the http proxy server username
	 */
	public final String getHttpProxyUsername() {
		return httpProxyUsername;
	}

	/**
	 * Returns the url of the backend to connect to.
	 * 
	 * @return the serviceInterface url
	 */
	public final String getLoginUrl() {

		if ((aliasMap != null)
				&& StringUtils.isNotBlank(aliasMap.get(loginUrl.toLowerCase()))) {
			return aliasMap.get(loginUrl.toLowerCase());
		} else {
			return loginUrl;
		}
	}

	/**
	 * Returns the myproxy password.
	 * 
	 * @return the myproxy password
	 */
	public final char[] getMyProxyPassphrase() {
		return myProxyPassphrase;
	}

	/**
	 * Returns the port of the myproxy server.
	 * 
	 * @return the myproxy server port
	 */
	public final String getMyProxyPort() {
		if (StringUtils.isNotBlank(myProxyPort)) {
			return myProxyPort;
		}
		String loginUrl = getLoginUrl();
		String myproxy = null;
		if (StringUtils.isNotBlank(loginUrl)) {
			if (myProxyMap != null) {
				myproxy = myProxyMap.get(loginUrl);
				if (StringUtils.isNotBlank(myproxy)) {

					Integer port = FileSystemHelpers.getPort(myproxy);
					if ((port != null) && (port > 0)) {
						myproxy = port.toString();
					}
				}
			}
		}

		if (StringUtils.isBlank(myproxy)) {
			myproxy = Integer.toString(GridEnvironment.getDefaultMyProxyPort());
		}

		return myproxy;
	}

	/**
	 * Returns the hostname of the myproxy server.
	 * 
	 * @return the myproxy server hostname
	 */
	public final String getMyProxyServer() {

		if (StringUtils.isNotBlank(myProxyServer)) {
			return myProxyServer;
		}

		String loginUrl = getLoginUrl();
		String myproxy = null;
		if (StringUtils.isNotBlank(loginUrl)) {
			if (myProxyMap != null) {
				myproxy = myProxyMap.get(loginUrl);
				if (StringUtils.isNotBlank(myproxy)) {
					myproxy = FileSystemHelpers.getHost(myproxy);
					if (StringUtils.isBlank(myproxy)) {
						myproxy = GridEnvironment.getDefaultMyProxyServer();
					}
				}
			}
		}

		return myproxy;
	}

	/**
	 * Returns the myproxy username.
	 * 
	 * @return the myproxy username
	 */
	public final String getMyProxyUsername() {
		return myProxyUsername;
	}

	public void setAliasMap(ImmutableBiMap<String, String> map) {
		this.aliasMap = map;
	}

	/**
	 * Sets the http proxy server port.
	 * 
	 * @param httpProxy
	 *            the http proxy server port
	 */
	public final void setHttpProxy(final String httpProxy) {
		this.httpProxy = httpProxy;
	}

	/**
	 * Sets the password for the http proxy server.
	 * 
	 * @param httpProxyPassphrase
	 *            the http proxy server password
	 */
	public final void setHttpProxyPassphrase(final char[] httpProxyPassphrase) {
		this.httpProxyPassphrase = httpProxyPassphrase;
	}

	/**
	 * Returns the port of the http proxy server.
	 * 
	 * @param httpProxyPort
	 *            the http proxy server port
	 */
	public final void setHttpProxyPort(final int httpProxyPort) {
		this.httpProxyPort = httpProxyPort;
	}

	/**
	 * Sets the http proxy server username.
	 * 
	 * @param httpProxyUsername
	 *            the username for the http proxy server
	 */
	public final void setHttpProxyUsername(final String httpProxyUsername) {
		this.httpProxyUsername = httpProxyUsername;
	}

	/**
	 * Sets the url of the backend to connect to.
	 * 
	 * @param loginUrl
	 *            the serviceInterface url
	 */
	public final void setLoginUrl(final String url) {


		this.loginUrl = url;

	}

	/**
	 * Sets a map that helps to choose myproxy servers depending on the login
	 * url.
	 * 
	 * This map is used if no myproxy server is explicitely set.
	 * 
	 * The key of the map would be the loginurl, the value the myproxy server in
	 * the format myproxyHost[:myproxyPort]
	 * 
	 * @param map
	 *            the translation map.
	 */
	public void setMyProxyMap(ImmutableMap<String, String> map) {
		this.myProxyMap = map;
	}

	/**
	 * Sets the myproxy password.
	 * 
	 * @param myProxyPassphrase
	 *            the myproxy password
	 */
	public final void setMyProxyPassphrase(final char[] myProxyPassphrase) {
		this.myProxyPassphrase = myProxyPassphrase;
	}

	/**
	 * Sets the port of the myproxy server.
	 * 
	 * @param myProxyPort
	 *            the myproxy server port to use
	 */
	public final void setMyProxyPort(final String myProxyPort) {
		this.myProxyPort = myProxyPort;
	}

	/**
	 * Sets the hostname of the myproxy server to use.
	 * 
	 * @param myProxyServer
	 *            the myproxy server hostname
	 */
	public final void setMyProxyServer(final String myProxyServer) {
		this.myProxyServer = myProxyServer;
	}

	/**
	 * Sets the myproxy username.
	 * 
	 * @param myProxyUsername
	 *            the myproxy username
	 */
	public final void setMyProxyUsername(final String myProxyUsername) {
		this.myProxyUsername = myProxyUsername;
	}

}
