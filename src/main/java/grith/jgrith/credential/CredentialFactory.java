package grith.jgrith.credential;

import grisu.jcommons.configuration.CommonGridProperties;
import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.dependencies.BouncyCastleTool;
import grisu.jcommons.exceptions.CredentialException;
import grisu.jcommons.utils.MyProxyServerParams;
import grisu.jcommons.view.cli.CliHelpers;
import grith.gsindl.SLCS;
import grith.jgrith.control.LoginParams;
import grith.jgrith.control.SlcsLoginWrapper;
import grith.jgrith.utils.CliLogin;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

public class CredentialFactory {

	static final Logger myLogger = LoggerFactory
			.getLogger(CredentialFactory.class.getName());

	public static String SLCS_URL = SLCS.DEFAULT_SLCS_URL;

	// public static String MYPROXY_HOST = Environment.getDefaultMyProxy()
	// .getHost();
	// public static int MYPROXY_PORT = Environment.getDefaultMyProxy()
	// .getPort();

	public static Credential createFromCommandline() {
		return createFromCommandline(Credential.DEFAULT_PROXY_LIFETIME_IN_HOURS);
	}

	public static Credential createFromCommandline(int proxy_lifetime_in_hours) {
		return createFromCommandline(null, proxy_lifetime_in_hours);
	}

	public static Credential createFromCommandline(LoginParams params,
			int proxy_lifetime_in_hours) {

		final String lastIdp = CommonGridProperties.getDefault()
				.getGridProperty(CommonGridProperties.Property.SHIB_IDP);

		final ImmutableSet<LoginType> temp;

		if (StringUtils.isBlank(lastIdp)) {
			temp = ImmutableSet.of(LoginType.SHIBBOLETH, LoginType.MYPROXY,
					LoginType.X509_CERTIFICATE);

		} else {
			temp = ImmutableSet.of(LoginType.SHIBBOLETH,
					LoginType.SHIBBOLETH_LAST_IDP, LoginType.MYPROXY,
					LoginType.X509_CERTIFICATE);

		}

		return createFromCommandline(params, temp, proxy_lifetime_in_hours);

	}

	public static Credential createFromCommandline(LoginParams params,
			Set<LoginType> types, int proxy_lifetime_in_hours) {

		if ((types == null) || (types.size() == 0)) {

			throw new IllegalArgumentException("No login type specified.");
		}

		String msg = "Please select your preferred login method:";

		final ImmutableList<LoginType> temp = ImmutableList.copyOf(types);
		List<String> typeStrings = new LinkedList<String>();
		for (int i = 0; i < temp.size(); i++) {
			if (temp.get(i).equals(LoginType.SHIBBOLETH_LAST_IDP)) {
				final String lastIdp = CommonGridProperties.getDefault()
						.getLastShibIdp();
				typeStrings.add(temp.get(i).getPrettyName() + " (using: "
						+ lastIdp + ")");
			} else {
				typeStrings.add(temp.get(i).getPrettyName());
			}
		}

		String choice = CliLogin.ask("Login method", null, typeStrings, msg,
				true);

		int index = typeStrings.indexOf(choice);

		LoginType type = temp.get(index);
		Credential cred = null;

		switch (type) {
		case X509_CERTIFICATE:
			cred = createFromLocalCertCommandline(proxy_lifetime_in_hours);
			break;
		case MYPROXY:

			cred = createFromMyProxyCommandline(params,
					proxy_lifetime_in_hours * 3600);
			break;
		case SHIBBOLETH:
			cred = createFromSlcsCommandline(proxy_lifetime_in_hours * 3600);
			break;
		case SHIBBOLETH_LAST_IDP:
			cred = createFromSlcsCommandline(CommonGridProperties
					.getDefault()
					.getLastShibIdp(), proxy_lifetime_in_hours * 3600);
			break;
		default:
			throw new IllegalArgumentException("Login type " + type
					+ " not supported");
		}

		if (params != null) {
			cred.setMyProxyDelegatedUsername(params.getMyProxyUsername());
			cred.setMyProxyDelegatedPassword(params.getMyProxyPassphrase());
		}

		return cred;
	}

	public static Credential createFromLocalCert(char[] passphrase,
			int lifetime_in_hours) {

		Credential cred = new X509Credential(passphrase, lifetime_in_hours);
		cred.setProperty(Credential.PROPERTY.LoginType,
				LoginType.X509_CERTIFICATE);
		return cred;

	}

	public static Credential createFromLocalCertCommandline() {
		return createFromLocalCertCommandline(Credential.DEFAULT_PROXY_LIFETIME_IN_HOURS);
	}

	public static Credential createFromLocalCertCommandline(
			int lifetime_in_hours) {

		char[] pw = CliLogin
				.askPassword("Please enter your certificate passphrase");
		return createFromLocalCert(pw, lifetime_in_hours);
	}

	public static Credential createFromMyProxy(String username,
			char[] password, int lifetime_in_seconds) {
		return createFromMyProxy(username, password, null, -1,
				lifetime_in_seconds);
	}

	public static Credential createFromMyProxy(String username,
			char[] password, String myProxyHost, int myProxyPort,
			int lifetime_in_seconds) {

		Credential cred = new MyProxyCredential(username, password, myProxyHost,
				myProxyPort, lifetime_in_seconds);
		cred.setProperty(Credential.PROPERTY.LoginType, LoginType.MYPROXY);

		CommonGridProperties.getDefault().setLastMyProxyUsername(username);

		return cred;
	}

	public static Credential createFromMyProxyCommandline(
			int lifetime_in_seconds) {
		return createFromMyProxyCommandline(null, lifetime_in_seconds);
	}

	public static Credential createFromMyProxyCommandline(LoginParams params,
			int lifetime_in_seconds) {

		String username = null;
		String host = null;
		int port = -1;

		if ((params == null)
				|| StringUtils.isBlank(params.getMyProxyUsername())) {
			username = CliLogin.ask("MyProxy username", CommonGridProperties
					.getDefault().getLastMyProxyUsername());
			if (params != null) {
				params.setMyProxyUsername(username);
			}
		} else {
			username = params.getMyProxyUsername();
			host = params.getMyProxyServer();
			port = Integer.parseInt(params.getMyProxyPort());
		}

		char[] password = null;
		if ((params == null) || (params.getMyProxyPassphrase() == null)) {
			password = CliLogin.askPassword("MyProxy password");
			if (params != null) {
				params.setMyProxyPassphrase(password);
			}
		} else {
			password = params.getMyProxyPassphrase();
		}

		CliHelpers.setIndeterminateProgress("Retrieving credential...", true);

		if ((params == null) || StringUtils.isBlank(params.getMyProxyServer())) {
			host = MyProxyServerParams.DEFAULT_MYPROXY_SERVER;
		} else {
			host = params.getMyProxyServer();
			int tempPort = Integer.parseInt(params.getMyProxyPort());
			if (tempPort > 0) {
				port = tempPort;
			}
		}
		if ( port <= 0 ) {
			port = MyProxyServerParams.DEFAULT_MYPROXY_PORT;
		}

		try {
			Credential cred = createFromMyProxy(username, password, host, port,
					lifetime_in_seconds);
			return cred;
		} finally {
			CliHelpers.setIndeterminateProgress(false);
		}

	}

	public static Credential createFromSlcs(String url, String idp,
			String username, char[] password, int lifetimeInSeconds) {

		final Credential c = new SLCSCredential(url, idp, username, password,
				true, lifetimeInSeconds);
		CommonGridProperties.getDefault().setLastShibUsername(username);
		CommonGridProperties.getDefault().setLastShibIdp(idp);

		return c;

	}

	public static Credential createFromSlcsCommandline() {
		return createFromSlcsCommandline(Credential.DEFAULT_PROXY_LIFETIME_IN_HOURS * 3600);
	}

	public static Credential createFromSlcsCommandline(int lifetimeInSeconds) {

		List<String> idps = null;
		try {
			CliHelpers.setIndeterminateProgress(
					"Loading list of institutions...", true);
			idps = SlcsLoginWrapper.getAllIdps();
		} catch (Throwable e) {
			throw new CredentialException("Could not list idps: "
					+ e.getLocalizedMessage());
		} finally {
			CliHelpers.setIndeterminateProgress(false);
		}

		System.out.println("");
		String lastIdp = CommonGridProperties.getDefault().getLastShibIdp();
		String idp = CliLogin.ask("Your institution", lastIdp, idps,
				"Please select the institution you are associated with:", true);

		if (StringUtils.isBlank(idp)) {
			System.exit(0);
		}

		return createFromSlcsCommandline(idp, lifetimeInSeconds);
	}

	public static Credential createFromSlcsCommandline(String idp,
			int lifetimeInSeconds) {

		String msg = "Your institution username";
		String lastUsername = CommonGridProperties.getDefault()
				.getLastShibUsername();

		String username = CliLogin.ask(msg, lastUsername);

		return createFromSlcsCommandline(username, idp, lifetimeInSeconds);

	}

	public static Credential createFromSlcsCommandline(String username,
			String idp, int lifetimeInSeconds) {

		char[] pw = CliLogin.askPassword("Your institution password");

		CliHelpers.setIndeterminateProgress("Logging in...", true);
		try {
			Credential cred = createFromSlcs(SLCS_URL, idp, username, pw,
					lifetimeInSeconds);
			return cred;
		} finally {
			CliHelpers.setIndeterminateProgress(false);
		}

	}

	public static Credential loadFromLocalProxy() {

		Credential cred = new ProxyCredential();
		cred.setProperty(Credential.PROPERTY.LoginType, LoginType.LOCAL_PROXY);
		return cred;

	}

	public static void main(String[] args) throws Exception {

		BouncyCastleTool.initBouncyCastle();

		Credential cred = createFromCommandline();

		cred.uploadMyProxy();

		System.out.println(cred.getMyProxyUsername());
		System.out.println(new String(cred.getMyProxyPassword()));

		// Credential cred = createFromSlcsCommandline();
		System.out.println(cred.getCredential().getRemainingLifetime());

		System.out.println("Enddate: " + cred.getEndDate().getTime());

	}

}
