package grith.jgrith;

import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.plainProxy.PlainProxy;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.globus.common.CoGProperties;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

public class X509Credential extends Credential {

	private final int lifetime_in_hours;

	private GSSCredential cred;

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
				DEFAULT_PROXY_LIFETIME_IN_HOURS, true);
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
	public X509Credential(String certFile, String keyFile, char[] certPassphrase,
			int lifetime_in_hours,
			boolean storePasspharseInMemory) throws CredentialException {

		addProperty(PROPERTY.CertFile, certFile);
		addProperty(PROPERTY.KeyFile, keyFile);
		this.lifetime_in_hours = lifetime_in_hours;

		addProperty(PROPERTY.LoginType, LoginType.X509_CERTIFICATE);

		Map<PROPERTY, Object> temp = new HashMap<PROPERTY, Object>(
				getProperties());
		temp.put(PROPERTY.Password, certPassphrase);

		createGssCredential(temp);

	}


	@Override
	public void createGssCredential(Map<PROPERTY, Object> conf)
			throws CredentialException {

		try {

			Map<PROPERTY, Object> temp = getDefaultRefresher().getConfig(this);
			temp.putAll(conf);

			char[] passphrase = (char[]) temp.get(PROPERTY.Password);
			if (passphrase == null) {
				throw new CredentialException("No passphrase provided.");
			}


			String certFile = (String) temp.get(PROPERTY.CertFile);
			String keyFile = (String) temp.get(PROPERTY.KeyFile);

			this.cred = PlainProxy.init(certFile, keyFile, passphrase,
					lifetime_in_hours);
		} catch (Exception e) {
			throw new CredentialException("Can't init certificate: "
					+ e.getLocalizedMessage(), e);
		}

	}

	@Override
	public void destroyCredential() {
	}

	@Override
	public GSSCredential getGSSCredential() throws CredentialException {
		return cred;
	}

}
