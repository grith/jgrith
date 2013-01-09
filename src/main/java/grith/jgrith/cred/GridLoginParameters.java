package grith.jgrith.cred;

import grisu.jcommons.configuration.CommonGridProperties;
import grisu.jcommons.configuration.CommonGridProperties.Property;
import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.certificate.CertificateHelper;
import grith.jgrith.cred.AbstractCred.PROPERTY;
import grith.jgrith.cred.callbacks.AbstractCallback;
import grith.jgrith.cred.callbacks.NoCallback;
import grith.jgrith.cred.details.IdPDetail;
import grith.jgrith.cred.details.PasswordDetail;
import grith.jgrith.cred.details.StringDetail;
import grith.jgrith.utils.CommandlineArgumentHelpers;

import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

public class GridLoginParameters {

	public static Logger myLogger = LoggerFactory
			.getLogger(GridLoginParameters.class);

	public static GridLoginParameters createFromCommandlineArgs(
			GridCliParameters params, String[] args) {

		// GridLoginParameters glp = new GridLoginParameters();
		try {
			
			String[] gridArgs = CommandlineArgumentHelpers.extractGridParameters(params, args);
			
			JCommander jc = new JCommander(params, gridArgs);

			if (params.isHelp()) {
				jc.usage();
				System.exit(0);
			}

			return createFromGridCliParameters(params);

		} catch (ParameterException pe) {
			throw new CredentialException("Can't parse cli parameters: "
					+ pe.getLocalizedMessage());
		}

	}

	public static GridLoginParameters createFromGridCliParameters(GridCliParameters settings) {
		GridLoginParameters glp = new GridLoginParameters();
		try {

			if (settings.isNologin()) {
				glp.setNologin(true);
				return glp;
			} else if (settings.isLogout()) {
				glp.setLogout(true);
				return glp;
			} else {
				if (settings.useX509Login()) {
					// x509
					char[] x509pw = settings.getPassword();
					glp.setLoginType(LoginType.X509_CERTIFICATE);
					glp.setPassword(x509pw);
				} else if (settings.useMyProxyLogin()) {
					glp.setLoginType(LoginType.MYPROXY);
					glp.setPassword(settings.getPassword());
					glp.setUsername(settings.getUsername());
				} else if (settings.useIdPLogin()) {
					// shib
					glp.setLoginType(LoginType.SHIBBOLETH);
					String institution = settings.getInstitution();
					glp.setInstitution(institution);
					glp.setUsername(settings.getUsername());
					glp.setPassword(settings.getPassword());
				}

				boolean useGridSession = settings.isStartGridSession();
				glp.setStartGridSessionDeamon(useGridSession);

				// String backend = settings.getBackend();
				// if (StringUtils.isNotBlank(backend)) {
				// glp.setBackend(backend);
				// }

				String myProxyHost = settings.getMyproxy_host();
				if (StringUtils.isNotBlank(myProxyHost)) {
					glp.setMyproxyHost(myProxyHost);
				}

				boolean forceAuth = settings.getForce();
				glp.setForceAuthenticate(forceAuth);

			}
		} catch (ParameterException pe) {
			throw new CredentialException("Can't parse cli parameters: "
					+ pe.getLocalizedMessage());
		}

		return glp;
	}

	public static GridLoginParameters fillFromCommandlineArgs(String[] args) {
		return createFromCommandlineArgs(new GridCliParameters(), args);
	}

	public static void main(String[] args) {

		GridLoginParameters p = fillFromCommandlineArgs(args);

		X509Cred c = new X509Cred();
		c.init(p.getCredProperties());

		System.out.println(c.getDN());

	}

	// private StringDetail backend = new StringDetail("backend",
	// "Please specify the grisu backend to login to");
	private boolean nologin = false;

	private boolean logout = false;
	private boolean forceAuthenticate = false;
	private StringDetail username = new StringDetail("username",
			"Please enter your username");

	private IdPDetail institution = new IdPDetail();
	private StringDetail myproxyHost = new StringDetail("myproxy_host",
			"Please enter the MyProxy host", false);
	private PasswordDetail password = new PasswordDetail();

	private StringDetail loginType = new StringDetail("login_type",
			"Please choose your login type");

	private AbstractCallback callback = new NoCallback();

	public boolean startGridSessionDeamon = false;

	public GridLoginParameters() {

		institution.assignGridProperty(Property.SHIB_IDP);
		// myproxyHost.assignGridProperty(Property.MYPROXY_HOST);
	}

	public Map<PROPERTY, Object> getCredProperties() {
		Map<PROPERTY, Object> result = Maps.newHashMap();

		if (loginType.isSet()) {
			result.put(PROPERTY.LoginType,
					LoginType.fromString(loginType.getValue()));
			if (LoginType.fromString(loginType.getValue()).equals(
					LoginType.MYPROXY)) {
				result.put(PROPERTY.MyProxyUsername, username.getValue());
				result.put(PROPERTY.MyProxyPassword, password.getValue());
			} else {
				result.put(PROPERTY.Username, username.getValue());
				result.put(PROPERTY.Password, password.getValue());
			}
		} else {
			result.put(PROPERTY.Username, username.getValue());
			result.put(PROPERTY.Password, password.getValue());
		}

		result.put(PROPERTY.IdP, institution.getValue());
		result.put(PROPERTY.MyProxyHost, myproxyHost.getValue());

		return result;
	}
	
	
	public String getInstitution() {
		return institution.getValue();
	}


	public LoginType getLoginType() {
		if (loginType == null) {
			return null;
		}
		return LoginType.fromString(loginType.getValue());
	}


	public String getMyProxyHost() {
		return myproxyHost.getValue();
	}

	public char[] getPassword() {
		return password.getValue();
	}

	public String getUsername() {
		return username.getValue();
	}

	public boolean isForceAuthenticate() {
		return forceAuthenticate;
	}

	public boolean isLogout() {
		return logout;
	}

	public boolean isNologin() {
		return nologin;
	}

	public boolean isStartGridSessionDeamon() {
		return startGridSessionDeamon;
	}

	public void populate() {

		LoginType lt = getLoginType();


		if ( lt == null ) {
			String idp = institution.getValue();
			if (StringUtils.isBlank(idp)) {
				idp = CommonGridProperties.getDefault().getLastShibIdp();
			}
			List<String> choices = Lists.newLinkedList();
			choices.add("Institution login");
			if (StringUtils.isNotBlank(idp)) {
				choices.add("Institution login (using: '" + idp + "')");
			}
			if (CertificateHelper.userCertExists()) {
				choices.add("Certificate login");
			}
			choices.add("MyProxy login");

			loginType.setChoices(choices);

			callback.fill(loginType);

			String ltString = loginType.getValue();

			if (StringUtils.isBlank(ltString)) {
				myLogger.debug("User selected to exit.");
				System.exit(0);
			} else if ("Institution login".equals(ltString)) {
				lt = LoginType.SHIBBOLETH;
				username.assignGridProperty(Property.SHIB_USERNAME);
			} else if (ltString.startsWith("Institution login (using")) {
				lt = LoginType.SHIBBOLETH;
				username.assignGridProperty(Property.SHIB_USERNAME);
				if (StringUtils.isNotBlank(idp)) {
					institution.set(idp);
				}
			} else if ("Certificate login".equals(ltString)) {
				lt = LoginType.X509_CERTIFICATE;
			} else if ("MyProxy login".equals(ltString)) {
				lt = LoginType.MYPROXY;
				username.assignGridProperty(Property.MYPROXY_USERNAME);
			} else {
				throw new CredentialException("LoginType " + ltString
						+ " not supported.");
			}

			loginType.set(lt.toString());

			switch(lt) {
			case SHIBBOLETH:
				String idpToUse = institution.getValue();
				if (StringUtils.isBlank(idpToUse)) {
					String answer = callback.getStringValue(institution);
					institution.set(answer);
				}
				if (! username.isSet() ) {
					String answer = callback.getStringValue(username);
					username.set(answer);
				}

				if (! password.isSet()) {
					char[] answer = callback.getPasswordValue(password);
					password.set(answer);
				}
				break;
			case X509_CERTIFICATE:
				if (!password.isSet()) {
					char[] answer = callback.getPasswordValue(password);
					password.set(answer);
				}
				break;
			case MYPROXY:
				if (!username.isSet()) {
					String answer = callback.getStringValue(username);
					username.set(answer);
				}
				if (!password.isSet()) {
					char[] answer = callback.getPasswordValue(password);
					password.set(answer);
				}
				break;

			default:
				throw new CredentialException("Login type: " + lt.toString()
						+ " not supported.");
			}

		}

		if (!validConfig()) {
			throw new CredentialException(
					"No valid credential after callbacks.");
		}


	}

	public void setCallback(AbstractCallback c) {
		this.callback =c;
	}

	private void setForceAuthenticate(boolean forceAuth) {
		this.forceAuthenticate = forceAuth;
	}

	// public void setBackend(String backend) {
	// this.backend.set(backend);
	// }

	public void setInstitution(String institution) {
		this.institution.set(institution);
	}

	public void setLoginType(LoginType loginType) {
		this.loginType.set(loginType.toString());
	}

	public void setLogout(boolean logout) {
		this.logout = logout;
	}

	public void setMyproxyHost(String myproxyHost) {
		this.myproxyHost.set(myproxyHost);
	}

	public void setNologin(boolean nologin) {
		this.nologin = nologin;
	}

	public void setPassword(char[] password) {
		this.password.set(password);
	}

	public void setStartGridSessionDeamon(boolean startGridSessionDeamon) {
		this.startGridSessionDeamon = startGridSessionDeamon;
	}

	public void setUsername(String username) {
		this.username.set(username);
	}

	public boolean validConfig() {

		if (isNologin() || isLogout()) {
			return false;
		}

		LoginType lt = getLoginType();

		if (lt == null) {
			return false;
		}

		switch (lt) {
		case MYPROXY:
			if (!institution.isSet() && username.isSet() && password.isSet()) {
				return true;
			} else {
				return false;
			}
		case SHIBBOLETH:
			if (institution.isSet() && username.isSet() && password.isSet()) {
				return true;
			} else {
				return false;
			}
		case X509_CERTIFICATE:
			if (password.isSet()) {
				return true;
			} else {
				return false;
			}

		default:
			return false;
		}

	}

}
