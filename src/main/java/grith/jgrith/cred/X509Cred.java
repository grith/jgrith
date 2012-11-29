package grith.jgrith.cred;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.cred.callbacks.AbstractCallback;
import grith.jgrith.cred.callbacks.StaticCallback;
import grith.jgrith.cred.details.FileDetail;
import grith.jgrith.cred.details.PasswordDetail;
import grith.jgrith.plainProxy.PlainProxy;

import java.util.Map;

import org.apache.commons.lang.StringUtils;
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

			String cert = certFile.getValue();
			String key = keyFile.getValue();

			return PlainProxy.init(cert, key,
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

	public String getPassword() {
		return new String(password.getValue());
	}

	@Override
	protected void initCred(Map<PROPERTY, Object> config) {

		char[] pwTemp = (char[]) config.get(PROPERTY.Password);

		Object certTemp = config.get(PROPERTY.CertFile);
		if ((certTemp == null) || StringUtils.isBlank((String) certTemp)) {
			if (StringUtils.isBlank(certFile.getValue())) {
				certTemp = CoGProperties.getDefault().getUserCertFile();
				certFile.set((String) certTemp);
			}
		} else {
			certFile.set((String) certTemp);
		}

		Object keyTemp = config.get(PROPERTY.KeyFile);
		if ((keyTemp == null) || StringUtils.isBlank((String) keyTemp)) {
			if (StringUtils.isBlank(keyFile.getValue())) {
				keyTemp = CoGProperties.getDefault().getUserKeyFile();
				keyFile.set((String) keyTemp);
			}
		} else {
			keyFile.set((String) keyTemp);
		}


		password.set(pwTemp);

	}

	@Override
	public boolean isRenewable() {
		return true;
	}
}
