package grith.jgrith.credential.refreshers;

import grisu.jcommons.configuration.CommonGridProperties;
import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.exceptions.CredentialException;
import grisu.jcommons.view.cli.CliHelpers;
import grith.jgrith.control.SlcsLoginWrapper;
import grith.jgrith.credential.Credential;
import grith.jgrith.credential.Credential.PROPERTY;
import grith.jgrith.utils.CliLogin;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import com.google.common.collect.Maps;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

public class CliCredentialRefresher extends CredentialRefresher {

	public static Map<PROPERTY, Object> createFromLocalCertCommandline() {

		char[] pw = CliLogin
				.askPassword("Please enter your certificate passphrase");
		Map<PROPERTY, Object> config = Maps.newHashMap();
		config.put(PROPERTY.Password, pw);
		return config;
	}

	private static Map<PROPERTY, Object> createFromMyProxyCommandline() {

		Map<PROPERTY, Object> config = Maps.newHashMap();
		String username = null;
		username = CliLogin.ask("MyProxy username", CommonGridProperties
				.getDefault().getLastMyProxyUsername());

		config.put(PROPERTY.Username, username);

		char[] password = null;
		password = CliLogin.askPassword("MyProxy password");

		config.put(PROPERTY.Password, password);

		return config;

	}

	public static Map<PROPERTY, Object> createFromSlcsCommandline() {

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
			return null;
		}

		return createFromSlcsCommandline(idp);

	}

	public static Map<PROPERTY, Object> createFromSlcsCommandline(
			String idp) {

		String msg = "Your institution username";
		String lastUsername = CommonGridProperties.getDefault()
				.getLastShibUsername();

		String username = CliLogin.ask(msg, lastUsername);
		char[] pw = CliLogin.askPassword("Your institution password");

		Map<PROPERTY, Object> config = Maps.newHashMap();
		config.put(PROPERTY.Password, pw);
		config.put(PROPERTY.Username, username);
		config.put(PROPERTY.IdP, idp);

		return config;

	}

	private Map<PROPERTY, Object> createFromCommandline(
			Credential t) {

		int proxy_lifetime_in_hours = t.getInitialLifetime();

		final String lastIdp = CommonGridProperties.getDefault()
				.getGridProperty(CommonGridProperties.Property.SHIB_IDP);

		final ImmutableSet<LoginType> temp;

		LoginType type = (LoginType) t.getProperty(PROPERTY.LoginType);
		if (type.equals(LoginType.UNDEFINED)
				|| type.equals(LoginType.LOCAL_PROXY)
				|| type.equals(LoginType.WRAPPED)) {

			if (StringUtils.isBlank(lastIdp)) {
				temp = ImmutableSet.of(LoginType.SHIBBOLETH, LoginType.MYPROXY,
						LoginType.X509_CERTIFICATE);

			} else {
				temp = ImmutableSet.of(LoginType.SHIBBOLETH,
						LoginType.SHIBBOLETH_LAST_IDP, LoginType.MYPROXY,
						LoginType.X509_CERTIFICATE);

			}
		} else {
			temp = ImmutableSet.of(type);
		}

		return createFromCommandline(temp, proxy_lifetime_in_hours);
	}

	private Map<PROPERTY, Object> createFromCommandline(Set<LoginType> types,
			int proxy_lifetime_in_hours) {
		if ((types == null) || (types.size() == 0)) {

			throw new IllegalArgumentException("No login type specified.");
		}

		LoginType type = null;
		if (types.size() == 1) {
			type = types.iterator().next();
		} else {

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

			type = temp.get(index);
		}

		Map<PROPERTY, Object> config = null;

		switch (type) {
		case X509_CERTIFICATE:
			config = createFromLocalCertCommandline();
			break;
		case MYPROXY:
			config = createFromMyProxyCommandline();
			break;
		case SHIBBOLETH:
			if (StringUtils.isBlank(CommonGridProperties.getDefault()
					.getLastShibIdp())
					|| StringUtils.isBlank(CommonGridProperties.getDefault()
							.getLastShibUsername())) {
				config = createFromSlcsCommandline();
				break;
			}
		case SHIBBOLETH_LAST_IDP:
			config = createFromSlcsCommandline(CommonGridProperties
					.getDefault()
					.getLastShibIdp());
			break;
		default:
			throw new IllegalArgumentException("Login type " + type
					+ " not supported");
		}

		if (config == null) {
			throw new CredentialException("Can't refresh credential.");
		}

		return config;

	}

	@Override
	protected Map<PROPERTY, Object> getConfig(Credential t) {

		return createFromCommandline(t);

	}

}
