package grith.jgrith;

import grisu.jcommons.configuration.CommonGridProperties;
import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.dependencies.BouncyCastleTool;
import grisu.jcommons.exceptions.CredentialException;
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
	public static String MYPROXY_HOST = Environment.getDefaultMyProxy()
			.getHost();
	public static int MYPROXY_PORT = Environment.getDefaultMyProxy()
			.getPort();

	public static Credential createFromCommandline() {
		return createFromCommandline(null);
	}

	public static Credential createFromCommandline(LoginParams params) {

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

		return createFromCommandline(params, temp);

	}

	public static Credential createFromCommandline(LoginParams params,
			Set<LoginType> types) {

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
			cred = createFromLocalCertCommandline();
			break;
		case MYPROXY:
			cred = createFromMyProxyCommandline(params,
					Credential.DEFAULT_PROXY_LIFETIME_IN_HOURS * 3600);
			break;
		case SHIBBOLETH:
			cred = createFromSlcsCommandline();
			break;
		case SHIBBOLETH_LAST_IDP:
			cred = createFromSlcsCommandline(CommonGridProperties
					.getDefault()
					.getLastShibIdp());
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

	public static Credential createFromLocalCert(char[] passphrase) {

		Credential cred = new X509Credential(passphrase);
		cred.setProperty(Credential.PROPERTY.LoginType,
				LoginType.X509_CERTIFICATE);
		return cred;

	}

	public static Credential createFromLocalCertCommandline() {

		char[] pw = CliLogin
				.askPassword("Please enter your certificate passphrase");
		return createFromLocalCert(pw);
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
		if ((params == null)
				|| StringUtils.isBlank(params.getMyProxyUsername())) {
			username = CliLogin.ask("MyProxy username", CommonGridProperties
					.getDefault().getLastMyProxyUsername());
			if (params != null) {
				params.setMyProxyUsername(username);
			}
		} else {
			username = params.getMyProxyUsername();
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
		try {
			Credential cred = createFromMyProxy(username, password, MYPROXY_HOST,
					MYPROXY_PORT, lifetime_in_seconds);
			return cred;
		} finally {
			CliHelpers.setIndeterminateProgress(false);
		}

	}

	public static Credential createFromSlcs(String url, String idp,
			String username,
			char[] password) {

		final Credential c = new SLCSCredential(url, idp, username, password,
				true);
		CommonGridProperties.getDefault().setLastShibUsername(username);
		CommonGridProperties.getDefault().setLastShibIdp(idp);

		return c;

	}

	public static Credential createFromSlcsCommandline() {

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

		return createFromSlcsCommandline(idp);
	}

	public static Credential createFromSlcsCommandline(String idp) {

		String msg = "Your institution username";
		String lastUsername = CommonGridProperties.getDefault()
				.getLastShibUsername();

		String username = CliLogin.ask(msg, lastUsername);

		return createFromSlcsCommandline(username, idp);

	}

	public static Credential createFromSlcsCommandline(String username,
			String idp) {

		char[] pw = CliLogin.askPassword("Your institution password");

		CliHelpers.setIndeterminateProgress("Logging in...", true);
		try {
			Credential cred = createFromSlcs(SLCS_URL, idp, username, pw);
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
