package grith.jgrith.cred;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.cred.details.FileDetail;
import grith.jgrith.utils.CredentialHelpers;

import java.io.File;
import java.io.FileInputStream;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.globus.common.CoGProperties;
import org.ietf.jgss.GSSCredential;

import com.beust.jcommander.internal.Maps;

public class ProxyCred extends AbstractCred {
	
	public static void main (String[] args) {
		
		ProxyCred p = new ProxyCred("/home/markus/.grid/grid.proxy");
		
		System.out.println(p.getDN());
		
	}

	protected FileDetail proxyFile = null;
	
	protected FileDetail getProxyFile() {
		if ( proxyFile == null ) {
			this.proxyFile = new FileDetail("X509 proxy file");
		}
		return proxyFile;
	}
	
	private static Map<PROPERTY, Object> createPropertyMap(String path) {
		Map<PROPERTY, Object> temp = Maps.newHashMap();
		temp.put(PROPERTY.LocalPath, path);
		return temp;
	}

	public ProxyCred(String path) throws CredentialException {
		super(createPropertyMap(path));
	}
	
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

		return CredentialHelpers.loadGssCredential(new File(getProxyFile()
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

		getProxyFile().set((String) proxyTemp);
		this.localPath = proxyFile.getValue();

		String mpFilePath = this.localPath
				+ BaseCred.DEFAULT_MYPROXY_FILE_EXTENSION;
		File mpFile = new File(mpFilePath);
		if (mpFile.exists()) {
			myLogger.debug("Loading credential myproxy metadata from {}...",
					mpFilePath);

			try {

				Properties props = new Properties();
				FileInputStream in = new FileInputStream(mpFile);
				props.load(in);
				in.close();

				String username = null;
				String host = null;
				int port = -1;
				char[] password = null;
				for (Object o : props.keySet()) {

					String key = (String) o;

					PROPERTY p = PROPERTY.valueOf(key);
					String value = props.getProperty(key);

					switch (p) {
					case MyProxyHost:
						host = value;
						break;
					case MyProxyUsername:
						username = value;
						break;
					case MyProxyPort:
						port = Integer.parseInt(value);
						break;
					case MyProxyPassword:
						password = value.toCharArray();
						break;
					default:
						throw new CredentialException("Property " + p
								+ " not supported.");
					}
				}

				if (StringUtils.isNotBlank(host)) {
					setMyProxyHost(host);
				}

				if (StringUtils.isNotBlank(username)) {
					setMyProxyUsername(username);
				}

				if (port > 0) {
					setMyProxyPort(port);
				}

				if (password != null) {
					setMyProxyPassword(password);
				}

				isUploaded = true;


			} catch (Exception e) {
				myLogger.error("Can't load myproxy metadata file", e);
			}

		} else {
			myLogger.debug("No myproxy metadata file found for cred.");
		}

	}

	@Override
	public boolean isRenewable() {
		return false;
	}

	@Override
	public String saveProxy() {
		String path = this.localPath;
		if ( StringUtils.isBlank(this.localPath)) {
			path = CoGProperties.getDefault().getProxyFile();
		}
		return saveProxy(path);
	}

	@Override
	public String saveProxy(String path) {

		// do nothing, it's already saved
		if ( isUploaded() ) {
			saveMyProxy(path);
		}

		if (! StringUtils.equals(path, this.localPath)) {
			return super.saveProxy(path);
		} else {
			return this.localPath;
		}


	}

	@Override
	public void uploadMyProxy(boolean force) {
		// in this case, we don't need force since the proxy can't be renewed anyway...
		super.uploadMyProxy(false);
	}

}
