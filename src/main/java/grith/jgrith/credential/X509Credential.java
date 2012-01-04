package grith.jgrith.credential;

import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.plainProxy.PlainProxy;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.globus.common.CoGProperties;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

public class X509Credential extends Credential {

	private char[] passphrase;

	/**
	 * Creates a Credential object from an x509 certificate and key pair that
	 * sits in the default globus location (usually $HOME/.globus/usercert.pem &
	 * userkey.pem) using the {@link #DEFAULT_PROXY_LIFETIME_IN_HOURS}.
	 * 
	 * @param passphrase
	 *            the certificate passphrase
	 * @throws CredentialException
	 *             if the proxy could not be created
	 */
	public X509Credential(char[] passphrase) throws CredentialException {
		this(CoGProperties.getDefault().getUserCertFile(), CoGProperties
				.getDefault().getUserKeyFile(), passphrase,
				Credential.DEFAULT_PROXY_LIFETIME_IN_HOURS, true);
	}

	/**
	 * Creates a Credential object from an x509 certificate and key pair that
	 * sits in the default globus location (usually $HOME/.globus/usercert.pem &
	 * userkey.pem).
	 * 
	 * @param passphrase
	 *            the certificate passphrase
	 * @param lifetime_in_hours
	 *            the lifetime of the proxy in hours
	 * @throws CredentialException
	 *             if the proxy could not be created
	 */
	public X509Credential(char[] passphrase, int lifetime_in_hours)
			throws CredentialException {
		this(CoGProperties.getDefault().getUserCertFile(), CoGProperties
				.getDefault().getUserKeyFile(), passphrase, lifetime_in_hours,
				true);
	}



	public X509Credential(Map<PROPERTY, Object> config) {
		super(config);
	}


	/**
	 * This one creates a Credential object by creating a proxy out of a local
	 * X509 certificate & key.
	 * 
	 * @param certFile
	 *            the path to the certificate
	 * @param keyFile
	 *            the path to the key
	 * @param certPassphrase
	 *            the passphrase for the certificate
	 * @param lifetime_in_hours
	 *            the lifetime of the proxy
	 * @throws IOException
	 * @throws GSSException
	 * @throws Exception
	 */
	public X509Credential(String certFile, String keyFile,
			char[] certPassphrase, int lifetime_in_hours,
			boolean storePasspharseInMemory) throws CredentialException {

		addProperty(PROPERTY.CertFile, certFile);
		addProperty(PROPERTY.KeyFile, keyFile);
		addProperty(PROPERTY.LifetimeInSeconds, lifetime_in_hours * 3600);
		addProperty(PROPERTY.StorePasswordInMemory, storePasspharseInMemory);

		addProperty(PROPERTY.LoginType, LoginType.X509_CERTIFICATE);

		if (storePasspharseInMemory) {
			this.passphrase = certPassphrase;
		}

		Map<PROPERTY, Object> temp = new HashMap<PROPERTY, Object>(
				getProperties());
		temp.put(PROPERTY.Password, certPassphrase);

		recreateGssCredential(temp);

	}

	@Override
	public Map<PROPERTY, Object> autorefreshConfig() {

		if (passphrase == null) {
			return null;
		}

		Map<PROPERTY, Object> temp = new HashMap<PROPERTY, Object>(
				getProperties());
		temp.put(PROPERTY.Password, passphrase);

		return temp;
	}

	@Override
	public GSSCredential createGssCredential(Map<PROPERTY, Object> temp)
			throws CredentialException {

		try {

			char[] passphrase = (char[]) temp.get(PROPERTY.Password);
			if (passphrase == null) {
				throw new CredentialException("No passphrase provided.");
			}

			Object store = getProperty(PROPERTY.StorePasswordInMemory);

			if ((store != null) && (Boolean) store) {
				this.passphrase = passphrase;
			}
			

			String certFile = (String) temp.get(PROPERTY.CertFile);
			String keyFile = (String) temp.get(PROPERTY.KeyFile);

			return PlainProxy.init(certFile, keyFile, passphrase,
					getInitialLifetime() / 3600);
		} catch (Exception e) {
			throw new CredentialException("Can't init certificate: "
					+ e.getLocalizedMessage(), e);
		}

	}

	@Override
	public void destroyCredential() {
	}

	@Override
	public boolean isAutoRenewable() {
		if ( passphrase == null) {
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
