package grith.jgrith.cred;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.cred.details.FileDetail;
import grith.jgrith.credential.Credential.PROPERTY;
import grith.jgrith.utils.CredentialHelpers;

import java.io.File;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.globus.common.CoGProperties;
import org.ietf.jgss.GSSCredential;

public class ProxyCred extends AbstractCred {

	protected FileDetail proxyFile = new FileDetail("X509 proxy file");

	public ProxyCred() throws CredentialException {
		super();
		try {
			init();
		} catch (Exception e) {
			throw new CredentialException("Can't create proxy: "
					+ e.getLocalizedMessage());
		}

	}

	@Override
	public GSSCredential createGSSCredentialInstance() {

		return CredentialHelpers.loadGssCredential(new File(proxyFile
				.getValue()));
	}

	@Override
	protected void initCred(Map<PROPERTY, Object> config) {

		Object proxyTemp = null;
		if (config != null) {

			proxyTemp = config.get(PROPERTY.LocalPath);
		}
		if ((proxyTemp == null) || !(proxyTemp instanceof String)
				|| StringUtils.isBlank((String) proxyTemp)) {
			proxyTemp = CoGProperties.getDefault().getProxyFile();
		}

		proxyFile.set((String) proxyTemp);
		this.localPath = proxyFile.getValue();

	}

	@Override
	public boolean isRenewable() {
		return false;
	}

	@Override
	public void saveProxy() {
		// do nothing, it's already saved
	}

	@Override
	public void saveProxy(String path) {

		// do nothing, it's already saved

		// if (StringUtils.isBlank(path)) {
		// path = CoGProperties.getDefault().getProxyFile();
		// }
		// synchronized (path) {
		//
		// this.localPath = path;
		//
		// CredentialHelpers.writeToDisk(getGSSCredential(), new File(
		// localPath));
		// }

	}

}
