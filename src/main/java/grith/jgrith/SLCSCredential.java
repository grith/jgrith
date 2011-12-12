package grith.jgrith;

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

	private GSSCredential cred;

	public SLCSCredential(String url, String idp, String username,
			char[] password, boolean storeLoginInfoInMemory) {
		myLogger.debug("SLCS login: setting idpObject and credentialManager...");

		addProperty(PROPERTY.SlcsUrl, url);
		addProperty(PROPERTY.IdP, idp);
		addProperty(PROPERTY.Username, username);

		if (storeLoginInfoInMemory) {
			getDefaultRefresher().addProperty(PROPERTY.Password, password);
		}

		Map<PROPERTY, Object> temp = new HashMap<PROPERTY, Object>(
				getProperties());
		temp.put(PROPERTY.Password, password);
		createGssCredential(temp);

	}

	@Override
	protected void createGssCredential(Map<PROPERTY, Object> config)
			throws CredentialException {

		try {

			Map<PROPERTY, Object> temp = new HashMap<PROPERTY, Object>(
					getDefaultRefresher().getConfig(this));
			temp.putAll(config);

			char[] password = (char[]) temp.get(PROPERTY.Password);
			if ((password == null) || (password.length == 0)) {
				throw new CredentialException("No password provided.");
			}

			String idp = (String) temp.get(PROPERTY.IdP);
			final IdpObject idpO = new StaticIdpObject(idp);
			String username = (String) temp.get(PROPERTY.Username);

			final CredentialManager cm = new StaticCredentialManager(username,
					password);

			myLogger.debug("SLCS login: starting actual login...");

			String url = (String) temp.get(PROPERTY.SlcsUrl);
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

			cred = PlainProxy.init(slcs.getCertificate(),
					slcs.getPrivateKey(), 24 * 10);
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
	public GSSCredential getGSSCredential() throws CredentialException {
		return cred;
	}




}
