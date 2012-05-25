package grith.jgrith.cred;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.cred.details.FileDetail;
import grith.jgrith.cred.details.PasswordDetail;
import grith.jgrith.credential.Credential.PROPERTY;
import grith.jgrith.plainProxy.PlainProxy;

import java.util.Map;

import org.globus.common.CoGProperties;
import org.ietf.jgss.GSSCredential;

public class X509Cred extends AbstractCred {

	public static X509Cred createFromConfig(Map<PROPERTY, Object> config) {

		char[] pw = (char[]) config.get(PROPERTY.Password);

		Object cert = config.get(PROPERTY.CertFile);
		if (cert == null) {
			cert = CoGProperties.getDefault().getUserCertFile();
		}

		Object key = config.get(PROPERTY.KeyFile);
		if (cert == null) {
			cert = CoGProperties.getDefault().getUserKeyFile();
		}

		X509Cred c = new X509Cred();
		c.password.set(pw);
		c.certFile.set((String) cert);
		c.keyFile.set((String) key);
		c.populate();

		return c;

	}
	protected FileDetail certFile = new FileDetail("X509 certificate file");
	protected FileDetail keyFile = new FileDetail("X509 key file");

	protected PasswordDetail password = new PasswordDetail(
			"X509 certificate password",
			"Please enter your certificate passphrase");

	public X509Cred() {
		this(CoGProperties.getDefault().getUserCertFile(), CoGProperties
				.getDefault().getUserKeyFile());
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
}
