package grith.jgrith.credential;

import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.plainProxy.LocalProxy;
import grith.jgrith.utils.CredentialHelpers;

import java.io.File;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.globus.util.Util;
import org.ietf.jgss.GSSCredential;

import com.google.common.collect.ImmutableMap;

public class ProxyCredential extends Credential {

	private final String localPathOrig;

	public ProxyCredential() {
		this(LocalProxy.PROXY_FILE);
	}

	/**
	 * Creates a Credential object out of an existing proxy file
	 *
	 * This proxy would usually be on the default globus location (e.g.
	 * /tmp/<x509u...> for Linux).
	 *
	 * @param config
	 *            the path to the proxy
	 * @throws CredentialException
	 *             if the credential at the specified path is not valid
	 */
	public ProxyCredential(Map<PROPERTY, Object> config) {

		for (PROPERTY p : config.keySet()) {
			Object value = config.get(p);
			setProperty(p, value);
		}

		this.localPathOrig = (String) config.get(PROPERTY.LocalPath);

		if (StringUtils.isBlank(this.localPathOrig)) {
			throw new CredentialException(
					"No local path specified for local proxy.");
		}

		File proxy = new File(this.localPathOrig);
		if (!proxy.exists()) {
			throw new CredentialException("No proxy found on: "
					+ this.localPathOrig);
		}

		addProperty(PROPERTY.LoginType, LoginType.LOCAL_PROXY);


		recreateGssCredential(null);


	}

	public ProxyCredential(String path) {
		this(new ImmutableMap.Builder().put(PROPERTY.LocalPath,
				path).build());
	}

	@Override
	public Map<PROPERTY, Object> autorefreshConfig() {
		return null;
	}

	@Override
	public GSSCredential createGssCredential(Map<PROPERTY, Object> config)
			throws CredentialException {


		try {
			return CredentialHelpers.loadGssCredential(new File(localPathOrig));
		} catch (CredentialException ce) {
			throw ce;
		} catch (Exception e) {
			throw new CredentialException("Can't load proxy file: "
					+ e.getLocalizedMessage(), e);
		}
	}


	@Override
	public void destroyCredential() {

		Util.destroy(localPathOrig);

	}


	@Override
	public String getLocalPath() {
		return this.localPathOrig;
	}

	@Override
	public boolean isAutoRenewable() {
		return false;
	}

	@Override
	public boolean isSaved() {
		return true;
	}

	@Override
	protected void setGssCredential(GSSCredential cred) {

		try {
			CredentialHelpers.writeToDisk(getCredential(), new File(
					localPathOrig));
			int initial_lifetime = cred.getRemainingLifetime();
			addProperty(PROPERTY.LifetimeInSeconds, initial_lifetime);
		} catch (Exception e) {
			throw new CredentialException("Can't load proxy file: "
					+ e.getLocalizedMessage(), e);
		}

	}

}
