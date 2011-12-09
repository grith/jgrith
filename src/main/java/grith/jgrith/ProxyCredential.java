package grith.jgrith;

import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.Credential.PROPERTY;
import grith.jgrith.plainProxy.LocalProxy;

import java.io.File;

import org.globus.util.Util;
import org.ietf.jgss.GSSCredential;

public class ProxyCredential extends Credential {
	
	private final String localPathOrig;
	private final GSSCredential cred;
	
	/**
	 * Creates a Credential object out of an existing proxy file
	 * 
	 * This proxy would usually be on the default globus location (e.g.
	 * /tmp/<x509u...> for Linux).
	 * 
	 * @param localPath
	 *            the path to the proxy
	 * @throws CredentialException
	 *             if the credential at the specified path is not valid
	 */
	public ProxyCredential(String localPath) {


		this.localPathOrig = localPath;

			File proxy = new File(localPath);
			if (!proxy.exists()) {
				throw new CredentialException("No proxy found on: " + localPath);
			}

			this.cred = CredentialHelpers.loadGssCredential(new File(localPath));
			
			addProperty(PROPERTY.LoginType, LoginType.LOCAL_PROXY);

	}
	
	public ProxyCredential() {
		this(LocalProxy.PROXY_FILE);
	}

	@Override
	public GSSCredential getCredential() throws CredentialException {
		return this.cred;
	}

	@Override
	public void destroyCredential() {

		Util.destroy(localPathOrig);
		
	}
	
	
	@Override
	public boolean isSaved() {
		return true;
	}
	
	@Override
	public String getLocalPath() {
		return this.localPathOrig;
	}

}
