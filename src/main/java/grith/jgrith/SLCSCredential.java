package grith.jgrith;

import java.util.Arrays;

import grisu.jcommons.constants.Constants;
import grisu.jcommons.exceptions.CredentialException;
import grith.gsindl.SLCS;
import grith.jgrith.plainProxy.PlainProxy;
import grith.sibboleth.CredentialManager;
import grith.sibboleth.IdpObject;
import grith.sibboleth.StaticCredentialManager;
import grith.sibboleth.StaticIdpObject;

import org.apache.commons.lang.StringUtils;
import org.ietf.jgss.GSSCredential;

public class SLCSCredential extends Credential {
	
	private GSSCredential cred;
	private String url;
	private String idp;
	private String username;
	private char[] password;
	
	public SLCSCredential(String url, String idp, String username, char[] password) {
		myLogger.debug("SLCS login: setting idpObject and credentialManager...");
		
		this.url = url;
		this.idp = idp;
		this.username = username;
		this.password = password;
		
		final IdpObject idpO = new StaticIdpObject(idp);
		final CredentialManager cm = new StaticCredentialManager(username,
				password);

		myLogger.debug("SLCS login: starting actual login...");

		if (StringUtils.isBlank(url)) {
			url = SLCS.DEFAULT_SLCS_URL;
		}

		final SLCS slcs = new SLCS(url, idpO, cm);
		if ((slcs.getCertificate() == null) || (slcs.getPrivateKey() == null)) {
			myLogger.debug("SLCS login: Could not get SLCS certificate and/or SLCS key...");
			throw new CredentialException(
					"Could not get SLCS certificate and/or SLCS key...");
		}

		myLogger.debug("SLCS login: Login finished.");
		myLogger.debug("SLCS login: Creating proxy from slcs credential...");

		cred = PlainProxy.init(slcs.getCertificate(),
				slcs.getPrivateKey(), 24 * 10);

	}
	


	@Override
	public GSSCredential getCredential() throws CredentialException {
		return cred;
	}

	@Override
	public void destroyCredential() {
		Arrays.fill(password, 'x');
	}




}
