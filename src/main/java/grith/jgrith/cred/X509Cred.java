package grith.jgrith.cred;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.cred.callbacks.AbstractCallback;
import grith.jgrith.cred.details.FileDetail;
import grith.jgrith.cred.details.PasswordDetail;
import grith.jgrith.credential.Credential.PROPERTY;
import grith.jgrith.plainProxy.PlainProxy;

import java.util.Map;

import org.globus.common.CoGProperties;
import org.ietf.jgss.GSSCredential;

public class X509Cred extends AbstractCred {

	protected FileDetail certFile = new FileDetail("X509 certificate file");
	protected FileDetail keyFile = new FileDetail("X509 key file");

	protected PasswordDetail password = new PasswordDetail(
			"X509 certificate password",
			"Please enter your certificate passphrase");

	public X509Cred() {
		this(CoGProperties.getDefault().getUserCertFile(), CoGProperties
				.getDefault().getUserKeyFile());
	}

	public X509Cred(AbstractCallback callback) {
		super(callback);
	}

	public X509Cred(AbstractCallback callback, String certFile, String keyFile) {
		super(callback);
		this.certFile.set(certFile);
		this.keyFile.set(keyFile);
		init();
	}

	public X509Cred(String certFile, String keyFile) {
		this.certFile.set(certFile);
		this.keyFile.set(keyFile);
	}

	@Override
	public GSSCredential createGSSCredentialInstance() {

		try {

			char[] passphrase = password.getValue();
			if (passphrase == null) {
				throw new CredentialException("No passphrase provided.");
			}

			return PlainProxy.init(certFile.getValue(), keyFile.getValue(),
					passphrase, getProxyLifetimeInSeconds() / 3600);
		} catch (Exception e) {
			throw new CredentialException("Can't init certificate: "
					+ e.getLocalizedMessage(), e);
		}

	}

	public String getCertificateFile() {
		return certFile.getValue();
	}

	public String getCertificateKey() {
		return keyFile.getValue();
	}

	public String getPw() {
		return new String(password.getValue());
	}

	@Override
	protected void initCred(Map<PROPERTY, Object> config) {

		char[] pwTemp = (char[]) config.get(PROPERTY.Password);

		Object certTemp = config.get(PROPERTY.CertFile);
		if (certTemp == null) {
			certTemp = CoGProperties.getDefault().getUserCertFile();
		}

		Object keyTemp = config.get(PROPERTY.KeyFile);
		if (keyTemp == null) {
			keyTemp = CoGProperties.getDefault().getUserKeyFile();
		}

		password.set(pwTemp);
		certFile.set((String) certTemp);
		keyFile.set((String) keyTemp);

	}
}