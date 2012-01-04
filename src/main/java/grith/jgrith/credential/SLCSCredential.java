package grith.jgrith.credential;

import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.exceptions.CredentialException;
import grith.gsindl.SLCS;
import grith.jgrith.plainProxy.PlainProxy;
import grith.sibboleth.CredentialManager;
import grith.sibboleth.IdpObject;
import grith.sibboleth.StaticCredentialManager;
import grith.sibboleth.StaticIdpObject;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.ietf.jgss.GSSCredential;

public class SLCSCredential extends Credential {

	private char[] password = null;

	public SLCSCredential(Map<PROPERTY, Object> config) {
		super(config);
	}

	public SLCSCredential(String idp, String username, char[] pw, boolean store) {
		this(SLCS.DEFAULT_SLCS_URL, idp, username, pw, store);
	}

	public SLCSCredential(String url, String idp, String username,
			char[] password, boolean storeLoginInfoInMemory) {
		this(url, idp, username, password, storeLoginInfoInMemory, -1);
	}

	public SLCSCredential(String url, String idp, String username,
			char[] password, boolean storeLoginInfoInMemory,
			int initialLifetimeInSeconds) {

		if (StringUtils.isBlank(url)) {
			url = SLCS.DEFAULT_SLCS_URL;
		}

		if (initialLifetimeInSeconds < 0) {
			addProperty(PROPERTY.LifetimeInSeconds,
					DEFAULT_PROXY_LIFETIME_IN_HOURS * 3600);
		} else {
			addProperty(PROPERTY.LifetimeInSeconds, initialLifetimeInSeconds);
		}
		addProperty(PROPERTY.SlcsUrl, url);
		addProperty(PROPERTY.IdP, idp);
		addProperty(PROPERTY.Username, username);
		addProperty(PROPERTY.LoginType, LoginType.SHIBBOLETH);
		addProperty(PROPERTY.StorePasswordInMemory, storeLoginInfoInMemory);

		if (storeLoginInfoInMemory) {
			this.password = password;
		}

		// we can't put password in default properties
		Map<PROPERTY, Object> temp = new HashMap<PROPERTY, Object>(
				getProperties());
		temp.put(PROPERTY.Password, password);
		recreateGssCredential(temp);

	}


	@Override
	public Map<PROPERTY, Object> autorefreshConfig() {

		if ( password == null ) {
			return null;
		}

		Map<PROPERTY, Object> temp = new HashMap<PROPERTY, Object>(
				getProperties());
		temp.put(PROPERTY.Password, password);
		return temp;
	}

	@Override
	public GSSCredential createGssCredential(Map<PROPERTY, Object> config)
			throws CredentialException {

		try {

			char[] password = (char[]) config.get(PROPERTY.Password);
			if ((password == null) || (password.length == 0)) {
				throw new CredentialException("No password provided.");
			}

			Object store = getProperty(PROPERTY.StorePasswordInMemory);

			if ((store != null) && (Boolean) store) {
				this.password = password;
			}

			String idp = (String) config.get(PROPERTY.IdP);
			final IdpObject idpO = new StaticIdpObject(idp);
			String username = (String) config.get(PROPERTY.Username);

			final CredentialManager cm = new StaticCredentialManager(username,
					password);

			myLogger.debug("SLCS login: starting actual login...");

			String url = (String) config.get(PROPERTY.SlcsUrl);
			if (StringUtils.isBlank(url)) {
				url = SLCS.DEFAULT_SLCS_URL;
			}

			final SLCS slcs = new SLCS(url, idpO, cm);
			if ((slcs.getCertificate() == null) || (slcs.getPrivateKey() == null)) {
				myLogger.error("SLCS login: Could not get SLCS certificate and/or SLCS key...");
				throw new CredentialException(
						"Could not get SLCS certificate and/or SLCS key.");
			}

			myLogger.debug("SLCS login: Login finished.");
			myLogger.debug("SLCS login: Creating proxy from slcs credential...");

			return PlainProxy.init(slcs.getCertificate(), slcs.getPrivateKey(),
					(getInitialLifetime() / 3600));
		} catch (Exception e) {
			throw new CredentialException("Could not create slcs credential: "
					+ e.getLocalizedMessage(), e);
		}
	}



	@Override
	public void destroyCredential() {
		// Arrays.fill(password, 'x');
	}

	@Override
	public boolean isAutoRenewable() {
		if ( password == null ) {
			return false;
		} else {
			return true;
		}
	}

	@Override
	protected void setGssCredential(GSSCredential cred) {
		// nothing to do here
	}

}
