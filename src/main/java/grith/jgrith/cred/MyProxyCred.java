package grith.jgrith.cred;

import grisu.jcommons.configuration.CommonGridProperties.Property;
import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.cred.callbacks.AbstractCallback;
import grith.jgrith.cred.details.PasswordDetail;
import grith.jgrith.cred.details.StringDetail;
import grith.jgrith.myProxy.MyProxy_light;

import java.io.File;
import java.io.FileInputStream;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.globus.common.CoGProperties;
import org.ietf.jgss.GSSCredential;

import com.google.common.collect.Maps;

public class MyProxyCred extends AbstractCred {

	public static MyProxyCred loadFromDefault() {

		File mpFile = new File(BaseCred.DEFAULT_MYPROXY_FILE_LOCATION);

		if (!mpFile.exists()) {
			throw new CredentialException(
					"No myproxy credential cache file exists in: "
							+ BaseCred.DEFAULT_MYPROXY_FILE_LOCATION);
		}

		MyProxyCred mp = new MyProxyCred(mpFile);
		return mp;

	}

	protected StringDetail username = new StringDetail("MyProxy username",
			"Please enter the MyProxy username");

	protected PasswordDetail pw = new PasswordDetail("MyProxy password",
			"Please enter the MyProxy password");

	protected StringDetail host = new StringDetail("MyProxy host",
			"Please specify the MyProxy host", false);
	protected int myproxyPort = 7512;

	public MyProxyCred() {
		this(null, null, null);
	}

	public MyProxyCred(AbstractCallback callback) {
		super(callback);
		init();
	}

	public MyProxyCred(File mpFile) {
		this();
		setSaveProxyOnCreation(false);
		initFromFile(mpFile.getAbsolutePath());
	}

	public MyProxyCred(String username) {
		this(username, null, null);
	}

	public MyProxyCred(String username, char[] password, String host) {
		this(username, password, host, GridEnvironment.getDefaultMyProxyPort());
	}

	public MyProxyCred(String username, char[] password, String host, int port,
			int lifetimeInSeconds) {
		this(username, password, host, port);
		setProxyLifetimeInSeconds(lifetimeInSeconds);
	}

	public MyProxyCred(String username, char[] password, String host, int port) {
		this(username, password, host, port, true);
	}

	public MyProxyCred(String username, char[] password, String host, int port,
			boolean saveProperties) {
		this(username, password, host, port, saveProperties, true);
	}

	public MyProxyCred(String username, char[] password, String host, int port,
			boolean saveProperties, boolean saveProxyOnCreation) {
		this(username, password, host, port, -1, saveProperties, saveProxyOnCreation);
	}
	
	public MyProxyCred(String username, char[] password, String host, int port, int lifetime,
				boolean saveProperties, boolean saveProxyOnCreation) {

		super(username, password, host, port);

		setSaveDetails(saveProperties);
		setSaveProxyOnCreation(saveProxyOnCreation);
		
		if ( lifetime > 0 ) {
			setProxyLifetimeInSeconds(lifetime);
		}

		if (StringUtils.isNotBlank(username)) {

			Map<PROPERTY, Object> config = Maps.newHashMap();
			config.put(PROPERTY.MyProxyUsername, username);
			config.put(PROPERTY.MyProxyPassword, password);
			config.put(PROPERTY.MyProxyHost, host);
			config.put(PROPERTY.MyProxyPort, port);

			init(config);
		}
	}

	public MyProxyCred(String username, String host) {
		this(username, null, host);
	}

	@Override
	public GSSCredential createGSSCredentialInstance() {

		char[] myproxyPassword = pw.getValue();
		String myproxyUsername = username.getValue();
		String myproxyhost = host.getValue();

		try {

			return MyProxy_light.getDelegation(myproxyhost, myproxyPort,
					myproxyUsername, myproxyPassword,
					getProxyLifetimeInSeconds());
		} catch (Exception e) {
			myLogger.error("Can't refresh myproxy credential.", e);
			throw new CredentialException("Can't retrieve MyProxy credential: "
					+ e.getLocalizedMessage(), e);
		}
	}

	@Override
	protected void initCred(Map<PROPERTY, Object> config) {

		try {

			String unTemp = null;
			try {
				unTemp = (String) config.get(PROPERTY.MyProxyUsername);
			} catch (NullPointerException npe) {
			}
			char[] passwordTemp = null;
			try {
				passwordTemp = (char[]) config.get(PROPERTY.MyProxyPassword);
			} catch (NullPointerException e) {
			}
			String hostTemp = null;
			try {
				hostTemp = (String) config.get(PROPERTY.MyProxyHost);
			} catch (NullPointerException npe) {
			}
			int portTemp = -1;
			try {
				portTemp = (Integer) config.get(PROPERTY.MyProxyPort);
			} catch (NullPointerException npe) {
			}

			this.username.assignGridProperty(Property.MYPROXY_USERNAME);
			// this.host.assignGridProperty(Property.MYPROXY_HOST);
			if (StringUtils.isNotBlank(hostTemp)) {
				this.host.set(hostTemp);
			}
			if (StringUtils.isNotBlank(unTemp)) {
				String temp = BaseCred.extractMyProxyServerFromUsername(unTemp);
				if (StringUtils.isNotBlank(temp)) {
					this.host.set(temp);
					this.username.set(BaseCred
							.extractUsernameFromUsername(unTemp));
				} else {
					this.username.set(unTemp);
				}
			}
			if ((passwordTemp != null) && (passwordTemp.length > 0)) {
				this.pw.set(passwordTemp);
			}

			initMyProxy(config);

		} catch (Exception e) {
			throw new CredentialException(
					"Can't create credential from config: "
							+ e.getLocalizedMessage());
		}

	}

	public void initFromFile() {
		initFromFile(DEFAULT_MYPROXY_FILE_LOCATION);
	}

	public void initFromFile(String path) {

		this.localMPPath = path;
		this.localPath = path.substring(0, path.length()
				- BaseCred.DEFAULT_MYPROXY_FILE_EXTENSION.length());

		myLogger.debug("Loading credential from file: " + path);
		try {
			Properties props = new Properties();
			FileInputStream in = new FileInputStream(path);
			props.load(in);
			in.close();

			Map<PROPERTY, Object> config = Maps.newHashMap();

			for (Object o : props.keySet()) {

				String key = (String) o;

				PROPERTY p = PROPERTY.valueOf(key);
				String value = props.getProperty(key);

				switch (p) {
				case MyProxyHost:
					config.put(p, value);
					break;
				case MyProxyUsername:
					config.put(p, value);
					break;
				case MyProxyPort:
					config.put(p, Integer.parseInt(value));
					break;
				case MyProxyPassword:
					config.put(p, value.toCharArray());
					break;
				default:
					throw new CredentialException("Property " + p
							+ " not supported.");
				}

			}

			init(config);
		} catch (Exception e) {
			throw new CredentialException(
					"Can't create credential from metadata file " + path + ": "
							+ e.getLocalizedMessage());
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

		// do nothing, if it's already saved
		if ( new File(path).exists() ) {
			return this.localPath;
		} else {
			super.saveProxy(path);
			return this.localPath;
		}

	}
	

	@Override
	public void uploadMyProxy(boolean force) {
		myLogger.debug("Not uploading, already myproxy...");
	}

}
