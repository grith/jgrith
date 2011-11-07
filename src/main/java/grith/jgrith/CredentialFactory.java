package grith.jgrith;

import grisu.jcommons.configuration.CommonGridProperties;
import grisu.jcommons.exceptions.CredentialException;
import grith.gsindl.SLCS;
import grith.jgrith.plainProxy.PlainProxy;
import grith.sibboleth.CredentialManager;
import grith.sibboleth.IdpObject;
import grith.sibboleth.StaticCredentialManager;
import grith.sibboleth.StaticIdpObject;

import org.ietf.jgss.GSSCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CredentialFactory {

	static final Logger myLogger = LoggerFactory
			.getLogger(CredentialFactory.class.getName());

	// public static Credential get

	public static Credential createFromLocalCert(char[] passphrase) {

		Credential cred = new Credential(passphrase);
		return cred;

	}

	public static Credential createFromMyProxy(String username, char[] password, String myProxyHost, int myProxyPort) {

		Credential cred = new Credential(username, password, myProxyHost, myProxyPort);

		return cred;
	}

	public static Credential createFromSlcs(String url, String idp,
			String username,
			char[] password) {

		myLogger.debug("SLCS login: setting idpObject and credentialManager...");
		final IdpObject idpO = new StaticIdpObject(idp);
		final CredentialManager cm = new StaticCredentialManager(username,
				password);

		myLogger.debug("SLCS login: starting actual login...");

		final SLCS slcs = new SLCS(url, idpO, cm);
		if ((slcs.getCertificate() == null) || (slcs.getPrivateKey() == null)) {
			myLogger.debug("SLCS login: Could not get SLCS certificate and/or SLCS key...");
			throw new CredentialException(
					"Could not get SLCS certificate and/or SLCS key...");
		}

		myLogger.debug("SLCS login: Login finished.");
		myLogger.debug("SLCS login: Creating proxy from slcs credential...");

		final GSSCredential gss = PlainProxy.init(slcs.getCertificate(),
				slcs.getPrivateKey(), 24 * 10);

		CommonGridProperties.getDefault().setLastShibUsername(username);
		CommonGridProperties.getDefault().setLastShibIdp(idp);

		Credential cred = new Credential(gss);
		return cred;

	}

}
