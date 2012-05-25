package grith.jgrith.cred;

import grisu.jcommons.configuration.CommonGridProperties.Property;
import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.cred.details.PasswordDetail;
import grith.jgrith.cred.details.StringDetail;
import grith.jgrith.credential.Credential.PROPERTY;
import grith.jgrith.myProxy.MyProxy_light;

import java.io.FileInputStream;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.ietf.jgss.GSSCredential;
import org.python.google.common.collect.Maps;

public class MyProxyCred extends AbstractCred {

	public static MyProxyCred createFromConfig(Map<PROPERTY, Object> config) {

		try {
			String un = (String) config.get(PROPERTY.MyProxyUsername);
			char[] pw = (char[]) config.get(PROPERTY.MyProxyPassword);
			String host = (String) config.get(PROPERTY.MyProxyHost);
			int port = (Integer) config.get(PROPERTY.MyProxyPort);

			MyProxyCred c = new MyProxyCred(un, pw, host, port);

			c.populate();

			return c;
		} catch (Exception e) {
			e.printStackTrace();
			throw new CredentialException(
					"Can't create credential from config: "
							+ e.getLocalizedMessage());
		}

	}

	public static MyProxyCred loadFromFile() {
		return loadFromFile(DEFAULT_MYPROXY_FILE_LOCATION);
	}

	public static MyProxyCred loadFromFile(String path) {

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

			return createFromConfig(config);
		} catch (Exception e) {
			e.printStackTrace();
			throw new CredentialException(
					"Can't create credential from metadata file " + path + ": "
							+ e.getLocalizedMessage());
		}

	}

	protected StringDetail username = new StringDetail("MyProxy username",
			"Please enter the MyProxy username");
	protected PasswordDetail pw = new PasswordDetail("MyProxy password",
			"Please enter the MyProxy password");

	protected StringDetail host = new StringDetail("MyProxy host",
			"Please specify the MyProxy host");

	protected int myproxyPort = 7512;

	public MyProxyCred() {
		this(null, null, null);
	}

	public MyProxyCred(String username) {
		this(username, null, null);
	}

	public MyProxyCred(String username, char[] password, String host) {
		this(username, password, host, GridEnvironment.getDefaultMyProxyPort());
	}

	public MyProxyCred(String username, char[] password, String host, int port) {
		super(username, password, host, port);
		this.username.assignGridProperty(Property.MYPROXY_USERNAME);
		this.host.assignGridProperty(Property.MYPROXY_HOST);
		if (StringUtils.isNotBlank(host)) {
			this.host.set(host);
		}
		if (StringUtils.isNotBlank(username)) {
			String temp = BaseCred.extractMyProxyServerFromUsername(username);
			if (StringUtils.isNotBlank(temp)) {
				this.host.set(temp);
				this.username.set(BaseCred
						.extractUsernameFromUsername(username));
			} else {
				this.username.set(username);
			}
		}
		if ((password != null) && (password.length > 0)) {
			this.pw.set(password);
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

}
