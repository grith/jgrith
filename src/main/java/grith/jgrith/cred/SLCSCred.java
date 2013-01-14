package grith.jgrith.cred;

import grisu.jcommons.configuration.CommonGridProperties.Property;
import grisu.jcommons.exceptions.CredentialException;
import grith.gsindl.SLCS;
import grith.jgrith.cred.callbacks.AbstractCallback;
import grith.jgrith.cred.details.IdPDetail;
import grith.jgrith.cred.details.PasswordDetail;
import grith.jgrith.cred.details.StringDetail;
import grith.jgrith.plainProxy.PlainProxy;
import grith.sibboleth.CredentialManager;
import grith.sibboleth.IdpObject;
import grith.sibboleth.StaticCredentialManager;
import grith.sibboleth.StaticIdpObject;

import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.ietf.jgss.GSSCredential;

public class SLCSCred extends AbstractCred {

	protected StringDetail slcs_url = new StringDetail("SLCS url",
			"Please provide the url for the SLCS server", false);

	protected IdPDetail idp = new IdPDetail();
	protected StringDetail username = new StringDetail("IdP username",
			"Please enter your institution username");


	protected PasswordDetail pw = new PasswordDetail("IdP password",
			"Please enter your institution passphrase");

	public SLCSCred() {
		super();
		username.assignGridProperty(Property.SHIB_USERNAME);
		idp.assignGridProperty(Property.SHIB_IDP);
		slcs_url.set(SLCS.DEFAULT_SLCS_URL);
	}

	public SLCSCred(AbstractCallback callback) {
		super(callback);
		username.assignGridProperty(Property.SHIB_USERNAME);
		idp.assignGridProperty(Property.SHIB_IDP);
		slcs_url.set(SLCS.DEFAULT_SLCS_URL);
	}

	@Override
	public GSSCredential createGSSCredentialInstance() {

		try {

			char[] password = pw.getValue();
			if ((password == null) || (password.length == 0)) {
				throw new CredentialException("No password provided.");
			}

			String idp_name = idp.getValue();
			final IdpObject idpO = new StaticIdpObject(idp_name);
			String username_name = username.getValue();

			final CredentialManager cm = new StaticCredentialManager(
					username_name, password);

			myLogger.debug("SLCS login: starting actual login...");

			String url = slcs_url.getValue();

			final SLCS slcs = new SLCS(url, idpO, cm);
			if ((slcs.getCertificate() == null)
					|| (slcs.getPrivateKey() == null)) {
				myLogger.error("SLCS login: Could not get SLCS certificate and/or SLCS key...");
				throw new CredentialException(
						"Could not get SLCS certificate and/or SLCS key.");
			}

			myLogger.debug("SLCS login: Login finished.");
			myLogger.debug("SLCS login: Creating proxy from slcs credential...");

			return PlainProxy.init(slcs.getCertificate(), slcs.getPrivateKey(),
					(getProxyLifetimeInSeconds() / 3600));
		} catch (Exception e) {
			throw new CredentialException("Could not create slcs credential: "
					+ e.getLocalizedMessage(), e);
		}
	}
	@Override
	protected void initCred(Map<PROPERTY, Object> config) {
		String idpTemp = (String) config.get(PROPERTY.IdP);
		char[] pwTemp = (char[]) config.get(PROPERTY.Password);
		String unTemp = (String) config.get(PROPERTY.Username);
		
		if (StringUtils.isNotBlank(idpTemp)) {
			idp.set(idpTemp);
		}
		if (StringUtils.isNotBlank(unTemp)) {
			username.set(unTemp);
		}

		pw.set(pwTemp);

	}

	@Override
	public boolean isRenewable() {
		return true;
	}

	public void setIdp(String idp) {
		this.idp.set(idp);
	}

	public void setSLCSurl(String url) {
		slcs_url.set(url);
	}

	public void setUsername(String un) {
		this.username.set(un);
	}

}
