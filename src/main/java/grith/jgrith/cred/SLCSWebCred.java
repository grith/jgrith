package grith.jgrith.cred;

import grisu.jcommons.exceptions.CredentialException;
import grith.gsindl.SLCS;
import grith.jgrith.cred.details.StringDetail;
import grith.jgrith.plainProxy.PlainProxy;
import grith.sibboleth.CredentialManager;
import grith.sibboleth.IdpObject;
import grith.sibboleth.Shibboleth;
import grith.sibboleth.StaticCredentialManager;
import grith.sibboleth.StaticIdpObject;

import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.ietf.jgss.GSSCredential;

import com.google.common.collect.Maps;

public class SLCSWebCred extends AbstractCred {
	
	private static Map<PROPERTY, Object> createPropertyMap(String response) {
		Map<PROPERTY, Object> temp = Maps.newHashMap();
		temp.put(PROPERTY.SlcsResponse, response);
		return temp;
	}
	
	public static void main(String[] args) {
		
		Shibboleth.initDefaultSecurityProvider();
		
		final String idp = "The University of Auckland";
		final String username = "mbin029";
		// I know, the password should be a char[]. But that doesn't work with
		// the jython bindings and it would be useless in
		// this case anyway since python uses plain strings in memory.
		final char[] password = args[0].toCharArray();

		IdpObject idpObject = new StaticIdpObject(idp);
		CredentialManager cm = new StaticCredentialManager(username, password);

		Shibboleth shibboleth = new Shibboleth(idpObject, cm);
		shibboleth.openurl(SLCS.DEFAULT_SLCS_URL);
		
		String response = shibboleth.getResponseAsString();
		
		SLCSWebCred cred = new SLCSWebCred(response);
		
		cred.saveProxy();
		
		System.out.println(cred.getDN());
		System.out.println(cred.getProxyLifetimeInSeconds()+" secs");
		
	}
	
	protected StringDetail slcs_response = new StringDetail("SLCS response",
			"Please provide the response xml string the SLCS server sent after a cert request", false);
	
	public SLCSWebCred() {
		super();
	}
	
	public SLCSWebCred(String slcsResponse) {
		super();
		setSlcsResponse(slcsResponse);
	}
	
	@Override
	public GSSCredential createGSSCredentialInstance() {
		
		try {

			myLogger.debug("SLCS cert creation: starting...");

			String response = slcs_response.getValue();

			final SLCS slcs = new SLCS(response);
			if ((slcs.getCertificate() == null)
					|| (slcs.getPrivateKey() == null)) {
				myLogger.error("SLCS creation: Could not get SLCS certificate and/or SLCS key...");
				throw new CredentialException(
						"Could not create SLCS certificate and/or SLCS key.");
			}

			myLogger.debug("SLCS creation: finished.");
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
		String responseTemp = (String) config.get(PROPERTY.SlcsResponse);
		
		if (StringUtils.isNotBlank(responseTemp)) {
			slcs_response.set(responseTemp);
		}
	}

	@Override
	public boolean isRenewable() {
		return false;
	}

	public void setSlcsResponse(String slcsResponseString) {
		this.slcs_response.set(slcsResponseString);
		if ( StringUtils.isNotBlank(slcsResponseString) ) {
			init(createPropertyMap(slcsResponseString));
		}
	}

}
