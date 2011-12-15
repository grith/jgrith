package grith.jgrith.credential;

import gridpp.portal.voms.VOMSAttributeCertificate;
import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.credential.refreshers.CredentialRefresher;
import grith.jgrith.myProxy.MyProxy_light;
import grith.jgrith.plainProxy.LocalProxy;
import grith.jgrith.plainProxy.PlainProxy;
import grith.jgrith.utils.CertHelpers;
import grith.jgrith.utils.CredentialHelpers;
import grith.jgrith.voms.VO;
import grith.jgrith.voms.VOManagement.VOManagement;
import grith.jgrith.vomsProxy.VomsHelpers;
import grith.jgrith.vomsProxy.VomsProxyCredential;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.globus.util.Util;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.python.google.common.collect.Maps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.Ostermiller.util.RandPass;
import com.google.common.collect.Lists;

/**
 * A wrapper class that wraps a {@link GSSCredential} and provides convenience
 * constructors and methods, like MyProxy- and VOMS-access and state management.
 * 
 * @author Markus Binsteiner
 * 
 */
public abstract class Credential {

	public enum PROPERTY {
		LoginType(LoginType.class),
		Username(String.class),
		Password(
				char[].class),
				MyProxyHost(String.class),
				MyProxyPort(
						Integer.class), VO(VO.class),
						FQAN(String.class),
						md5sum(String.class),
						SlcsUrl(String.class),
						IdP(String.class),
						CertFile(String.class),
						KeyFile(String.class),
						MyProxyPassword(char[].class),
						MyProxyUsername(String.class),
						LifetimeInSeconds(
								Integer.class), LocalPath(String.class), Uploaded(Boolean.class);

		private Class valueClass;

		private PROPERTY(Class valueClass) {
			this.valueClass = valueClass;
		}

		public Class getValueClass() {
			return valueClass;
		}
	}


	static final Logger myLogger = LoggerFactory.getLogger(Credential.class
			.getName());

	public final static String DEFAULT_MYPROXY_SERVER = GridEnvironment
			.getDefaultMyProxyServer();

	public final static int DEFAULT_MYPROXY_PORT = GridEnvironment
			.getDefaultMyProxyPort();

	public final static int MIN_REMAINING_LIFETIME = 600;

	public static final String METADATA_FILE_EXTENSION = "md";

	public static final String CHILD_KEY = "group";

	public static final int DEFAULT_PROXY_LIFETIME_IN_HOURS = 240;

	public static GSSCredential createFromCertificateAndKey(String certFile,
			String keyFile, char[] certPassphrase, int lifetime_in_hours) {
		return PlainProxy.init(certFile, keyFile, certPassphrase,
				lifetime_in_hours);
	}

	/**
	 * Reads the credential and returns the (first) fqan of its attached
	 * AttributeCertificate.
	 * 
	 * @param gss
	 *            the credential
	 * @return the fqan
	 * @throws CredentialException
	 *             if the credential is not voms enabled
	 */
	public static String getFqan(GSSCredential gss) throws CredentialException {

		VomsProxyCredential voms = new VomsProxyCredential(
				CredentialHelpers.unwrapGlobusCredential(gss));

		VOMSAttributeCertificate vomsac = new VOMSAttributeCertificate(
				voms.getAttributeCertificate());

		List<String> fqans = vomsac.getVOMSFQANs();
		if (fqans.size() == 0) {
			throw new CredentialException("Credential is not voms enabled");
		}
		String fqan = VomsHelpers.removeRoleAndCapabilityPart(fqans.get(0));
		return fqan;
	}

	public static Credential loadFromConfig(Map<PROPERTY, Object> config) {

		myLogger.debug("Loading credential from config map...");

		try {

			LoginType type = (LoginType)config.get(PROPERTY.LoginType);

			if ( type == null ) {
				throw new CredentialException("No credential type specified.");
			}


			String localPath = (String)config.get(PROPERTY.LocalPath);

			Credential c = null;
			switch (type) {
			case MYPROXY:
				c = new MyProxyCredential(config);
				break;
			case SHIBBOLETH:
			case SHIBBOLETH_LAST_IDP:
				c = new SLCSCredential(config);
				break;
			case X509_CERTIFICATE:
				c = new X509Credential(config);
				break;
			default:
				throw new CredentialException("Login type " + type.toString()
						+ " not supported.");
			}


			if (StringUtils.isNotBlank(localPath)
					&& new File(localPath).exists()) {
				c.setSaved(true);
				try {
					myLogger.debug("Loading gss credential from local proxy...");
					c.createFromLocalProxy();
					myLogger.debug("Credential loaded successfully.");
				} catch (CredentialException ce) {
					myLogger.error("Can't load from local proxy: "
							+ ce.getLocalizedMessage());
				}
			} else {
				myLogger.debug("Loading gss credential from MyProxy...");
				c.createFromMyProxy();
				myLogger.debug("Credential loaded successfully.");
				if (StringUtils.isNotBlank(localPath)
						&& !new File(localPath).exists()) {
					myLogger.debug("Saving gss credential data to local disk.");
					c.saveCredential(localPath);
				}
			}


			return c;
		} catch (CredentialException ce) {
			throw ce;
		} catch (Exception e) {
			throw new CredentialException("Can't create credential: "
					+ e.getLocalizedMessage(), e);
		}

	}

	public static Credential loadFromMetaDataFile(String metadataFile) {

		myLogger.debug("Loading credential from file: " + metadataFile);
		try {
			Properties props = new Properties();
			FileInputStream in = new FileInputStream(metadataFile);
			props.load(in);
			in.close();

			Map<PROPERTY, Object> config = Maps.newHashMap();

			Map<String, Map<PROPERTY, Object>> childs = Maps.newTreeMap();

			for (Object o : props.keySet()) {

				String key = (String) o;

				if (key.startsWith(CHILD_KEY)) {

					String[] tokens = key.split("\\.");

					String fqan = tokens[1];
					PROPERTY property = PROPERTY.valueOf(tokens[2]);
					String value = props.getProperty(key);
					Map<PROPERTY, Object> ptemp = childs.get(fqan);
					if (ptemp == null) {
						ptemp = Maps.newHashMap();
						ptemp.put(PROPERTY.FQAN, fqan);
						childs.put(fqan, ptemp);
					}
					switch (property) {
					case MyProxyPassword:
						ptemp.put(property, value.toCharArray());
						break;
					case MyProxyPort:
						ptemp.put(property, Integer.parseInt(value));
						break;
					default:
						ptemp.put(property, value);
						break;
					}

				} else {

					PROPERTY p = PROPERTY.valueOf(key);
					String value = props.getProperty(key);

					switch (p) {
					case CertFile:
					case FQAN:
					case IdP:
					case KeyFile:
					case LocalPath:
					case md5sum:
					case MyProxyHost:
					case MyProxyUsername:
					case SlcsUrl:
					case Username:
						config.put(p, value);
						break;
					case LifetimeInSeconds:
					case MyProxyPort:
						Integer lt = Integer.parseInt(value);
						config.put(p, lt);
						break;
					case MyProxyPassword:
						char[] pw = value.toCharArray();
						config.put(p, pw);
						break;
					case VO:
						VO vo = VOManagement.getVO(value);
						if (vo == null) {
							throw new CredentialException("Can't find vo: "
									+ value);
						}
						config.put(p, vo);
						break;
					case LoginType:
						config.put(p, LoginType.fromString(value));
						break;
					case Uploaded:
						config.put(p, Boolean.valueOf(value));
						break;
					default:
						throw new CredentialException("Property " + p
								+ " not supported.");
					}
				}

			}

			Credential c = loadFromConfig(config);

			for (String fqan : childs.keySet()) {
				myLogger.debug("Adding existing and uploaded childs to credential...");
				Map<PROPERTY, Object> childConf = childs.get(fqan);
				childConf.put(PROPERTY.LoginType, LoginType.MYPROXY);
				Credential child = loadFromConfig(childConf);
				c.addVomsCredential(child);
			}

			return c;
		} catch (Exception e) {
			throw new CredentialException("Can't create credential from metadata file: "+metadataFile);
		}

	}

	private final List<CredentialRefresher> refreshUI = Lists.newArrayList();

	private final UUID uuid = UUID.randomUUID();

	private Map<String, VO> fqans;

	private Calendar endTime;
	private int minLifetimeInSeconds = 300;

	private final long minTimeBetweenAutoRefreshes = 300;

	private volatile Date lastCredentialAutoRefresh = new Date();

	private GSSCredential cred;

	private final Map<PROPERTY, Object> properties;

	private final Map<String, Credential> children = Maps.newConcurrentMap();

	private boolean isSaved = false;

	public Credential() {
		myLogger.debug("Creating credential " + uuid);
		properties = Maps.newHashMap();
	}

	public Credential(Map<PROPERTY, Object> config) {
		if (config == null) {
			throw new CredentialException("No configuration specified.");
		}
		this.properties = config;

	}

	public void addCredentialRefreshIUI(CredentialRefresher ui) {
		myLogger.debug("Adding credential refresher of type "
				+ ui.getClass().getSimpleName());
		this.refreshUI.add(ui);
	}

	public void addProperty(PROPERTY key, Object value) {

		Class expectedClass = key.getValueClass();
		Class valueClass = value.getClass();

		if (!expectedClass.equals(valueClass)) {
			throw new CredentialException("Value needs to be of class "
					+ expectedClass.getName());
		}

		this.properties.put(key, value);
	}


	private void addVomsCredential(Credential child) {

		String fqan = child.getFqan();
		if ( StringUtils.isBlank(fqan)) {
			throw new CredentialException("Credential is not voms credential.");
		}
		children.put(fqan, child);

	}


	public boolean autorefresh() {

		myLogger.debug("Trying to autorefresh credential " + uuid);

		try {
			int ltOld = 0;
			try {
				ltOld = this.cred.getRemainingLifetime();
				myLogger.debug("Lifetime before autorefresh: " + ltOld);
			} catch (Exception e) {
			}

			if (!recreateGssCredential(autorefreshConfig())) {
				myLogger.debug("Recreating gss credential failed. Autorefresh not successful.");
				return false;
			}

			int ltNew = this.cred.getRemainingLifetime();
			myLogger.debug("Lifetime after autorefresh: " + ltNew);
			if (ltOld < ltNew) {
				return true;
			} else {
				return false;
			}
		} catch (Exception e) {
			myLogger.error(
					"Can't autorefresh x509 credential: "
							+ e.getLocalizedMessage(), e);
			return false;
		}

	}

	public abstract Map<PROPERTY, Object> autorefreshConfig();


	protected void createFromLocalProxy() {
		Map<PROPERTY, Object> config = getProperties();
		try {
			String localPath = (String) config.get(PROPERTY.LocalPath);
			if (StringUtils.isNotBlank(localPath)
					&& new File(localPath).exists()) {
				File f = new File(localPath);

				if (!f.canRead()) {
					throw new CredentialException("Can't read file: "
							+ localPath);
				}
				// check md5 sum
				String proxy = null;
				try {
					proxy = FileUtils.readFileToString(f);
				} catch (IOException e1) {
					myLogger.error("Can't read proxy file " + localPath, e1);
				}
				String md5 = DigestUtils.md5Hex(proxy);

				if (!md5.equals(config.get(PROPERTY.md5sum))) {
					throw new CredentialException(
							"mds5sum of proxy file mismatches.");
				}
				GSSCredential gss = CredentialHelpers.loadGssCredential(f);
				setCredential(gss);


			}
		} catch (Exception e) {
			throw new CredentialException(
					"Could not create credential from local proxy: "
							+ e.getLocalizedMessage(), e);
		}
	}

	protected void createFromMyProxy() {
		Map<PROPERTY, Object> config = getProperties();
		try {
			char[] pw = (char[]) config.get(PROPERTY.MyProxyPassword);

			String un = (String) config.get(PROPERTY.MyProxyUsername);
			String host = (String) config.get(PROPERTY.MyProxyHost);

			Integer port = (Integer) config.get(PROPERTY.MyProxyPort);

			GSSCredential cred = MyProxy_light.getDelegation(host, port, un,
					pw, getInitialLifetime());
			setCredential(cred);
		} catch (Exception e) {
			myLogger.error("Can't retrieve myproxy credential.", e);
			throw new CredentialException("Can't retrieve MyProxy credential: "
					+ e.getLocalizedMessage(), e);
		}
	}



	protected abstract GSSCredential createGssCredential(
			Map<PROPERTY, Object> config)
					throws CredentialException;

	/**
	 * Destroys proxy and possibly metadata file
	 */
	public void destroy() {

		myLogger.debug("Destroying credential " + uuid);

		destroyCredential();

		try {
			getGSSCredential().dispose();
		} catch (Exception e) {
			// that's ok
		}

		String localPath = (String) getProperty(PROPERTY.LocalPath);
		if (StringUtils.isNotBlank(localPath)) {
			if (new File(localPath).exists()) {
				myLogger.debug("Deleting proxy file " + localPath);
				Util.destroy(localPath);
			}
		}

		if (isUploaded()) {

			myLogger.debug("Destrying uploaded proxy from host: "
					+ getMyProxyServer());
			MyProxy mp = new MyProxy(getMyProxyServer(), getMyProxyPort());
			try {
				mp.destroy(getGSSCredential(), getMyProxyUsername(),
						new String(getMyProxyPassword()));
			} catch (MyProxyException e) {
				myLogger.error("Can't destroy myproxy credential.", e);
			}

			Arrays.fill(getMyProxyPassword(), 'x');
		}

	}


	public abstract void destroyCredential();

	@Override
	public boolean equals(Object o) {
		if (o instanceof Credential) {
			Credential other = (Credential) o;
			try {
				return getGSSCredential().equals(
						((Credential) o).getGSSCredential());
			} catch (CredentialException e) {
				return false;
			}

		} else {
			return false;
		}

	}

	/**
	 * Get a map of all Fqans (and VOs) the user has access to.
	 * 
	 * @return the Fqans of the user
	 */
	public synchronized Map<String, VO> getAvailableFqans() {

		if (fqans == null) {
			fqans = VOManagement.getAllFqans(getCredential());
		}
		return fqans;

	}

	public GSSCredential getCredential() throws InvalidCredentialException {

		GSSCredential c = getGSSCredential();
		try {
			int remaining = c.getRemainingLifetime();
			Date now = new Date();
			long diff = (now.getTime() - lastCredentialAutoRefresh.getTime()) / 1000;

			if ((diff > minTimeBetweenAutoRefreshes)
					&& (remaining < minLifetimeInSeconds)) {

				autorefresh();

				if ((cred == null) || (cred.getRemainingLifetime() <= 0)) {
					throw new InvalidCredentialException("Credential expired.");
				}
			}
		} catch (GSSException e) {
			throw new InvalidCredentialException(e);
		}
		return c;

	}

	public String getDn() {
		return CertHelpers.getDnInProperFormat(getCredential());
	}

	public Calendar getEndDate() {
		if (this.endTime == null) {
			endTime = Calendar.getInstance();
			endTime.add(Calendar.SECOND, getRemainingLifetime());
		}
		return endTime;
	}

	public String getFqan() {
		try {
			return getFqan(getCredential());
		} catch (CredentialException e) {
			return null;
		}
	}

	protected GSSCredential getGSSCredential() throws CredentialException {
		if (this.cred == null) {
			myLogger.debug("No credential found, creating it from the implementing class.");
			this.cred = createGssCredential(getProperties());
		}
		return this.cred;
	}

	public int getInitialLifetime() {
		Integer lt = (Integer) getProperties().get(PROPERTY.LifetimeInSeconds);

		if ((lt == null) || (lt <= 0)) {
			lt = DEFAULT_PROXY_LIFETIME_IN_HOURS * 3600;
		}
		return lt;
	}

	public String getLocalPath() {

		String localPath = (String) getProperty(PROPERTY.LocalPath);
		if (StringUtils.isBlank(localPath)) {
			localPath = LocalProxy.PROXY_FILE;
		}
		return localPath;
	}

	public int getMinLifetime() {
		return minLifetimeInSeconds;
	}

	/**
	 * Returns the myproxy password for this credential.
	 * 
	 * If this Creential was created from a MyProxy username/password
	 * combination to start with, this method will return the original MyProxy
	 * password. If not, it will create a random one. In the latter case, you
	 * need to call {@link #uploadMyProxy()} or
	 * {@link #uploadMyProxy(String, int)} before you can use this.
	 * 
	 * @return the MyProxy password to access this credential
	 */
	public char[] getMyProxyPassword() {

		if (getProperty(PROPERTY.MyProxyPassword) == null) {
			myLogger.debug("No myproxy password set, creating random one");
			setProperty(PROPERTY.MyProxyPassword,
					new RandPass().getPassChars(10));
		}
		return (char[]) getProperty(PROPERTY.MyProxyPassword);
	}

	public int getMyProxyPort() {
		if (getProperty(PROPERTY.MyProxyPort) == null) {
			setProperty(PROPERTY.MyProxyPort, DEFAULT_MYPROXY_PORT);
		}
		return (Integer) getProperty(PROPERTY.MyProxyPort);
	}

	/**
	 * The MyProxy host where this credential can be retrieved from.
	 * 
	 * If this Credential was created from MyProxy to start with, this will
	 * return the original MyProxy host. Otherwise it will return the MyProxy
	 * host that was used when uploading it via
	 * {@link #uploadMyProxy(String, int)}.
	 * 
	 * @return the MyProxy host
	 */
	public String getMyProxyServer() {
		if (getProperty(PROPERTY.MyProxyHost) == null) {
			setProperty(PROPERTY.MyProxyHost, DEFAULT_MYPROXY_SERVER);
		}
		return (String) getProperty(PROPERTY.MyProxyHost);
	}

	/**
	 * Returns the myproxy username for this credential.
	 * 
	 * If this Creential was created from a MyProxy username/password
	 * combination to start with, this method will return the original MyProxy
	 * username. If not, it will create a random one. In the latter case, you
	 * need to call {@link #uploadMyProxy()} or
	 * {@link #uploadMyProxy(String, int)} before you can use this.
	 * 
	 * @return the MyProxy password to access this credential
	 */
	public String getMyProxyUsername() {

		if (getProperty(PROPERTY.MyProxyUsername) == null) {
			myLogger.debug("No myproxy username set, creating random one");
			setProperty(PROPERTY.MyProxyUsername, UUID.randomUUID().toString());
		}
		return (String) getProperty(PROPERTY.MyProxyUsername);

	}

	public Map<PROPERTY, Object> getProperties() {
		return properties;
	}

	public Object getProperty(PROPERTY p) {
		return properties.get(p);
	}

	/**
	 * The remaining lifetime in seconds.
	 * 
	 * @return the lifetime
	 * @throws CredentialException
	 *             if the credential lifetime is shorther than
	 *             {@link #MIN_REMAINING_LIFETIME} or if the lifetime can't be
	 *             read from underlying credential.
	 */
	public int getRemainingLifetime() throws CredentialException {

		try {
			int lt = getCredential().getRemainingLifetime();
			return lt;
		} catch (GSSException e) {
			throw new CredentialException(
					"Can't get remaining lifetime from credential.", e);
		}
	}

	/**
	 * Creates a (new) voms-enabled credential object.
	 * 
	 * This method throws a CredentialException if the fqan is not available for
	 * the user when looking up all system-default VOs (the ones that have
	 * vomses files in $HOME/.glite/vomses or /etc/vomses).
	 * 
	 * @param fqan
	 *            the fqan
	 * @return the voms-enabled Credential
	 * @throws CredentialException
	 *             if the fqan is not available for the user
	 */
	public Credential getVomsCredential(String fqan) throws CredentialException {
		return getVomsCredential(fqan, false);
	}

	/**
	 * Creates a (new) voms-enabled credential object.
	 * 
	 * This method throws a CredentialException if the fqan is not available for
	 * the user when looking up all system-default VOs (the ones that have
	 * vomses files in $HOME/.glite/vomses or /etc/vomses).
	 * 
	 * @param fqan
	 *            the fqan
	 * @param upload
	 *            whether to upload the voms proxy to myproxy
	 * @return the voms-enabled Credential
	 * @throws CredentialException
	 *             if the fqan is not available for the user
	 */
	public Credential getVomsCredential(String fqan, boolean upload)
			throws CredentialException {

		VO vo = getAvailableFqans().get(fqan);
		if (vo == null) {
			throw new CredentialException("Can't find VO for fqan: " + fqan);
		} else {
			return getVomsCredential(vo, fqan, upload);
		}

	}

	/**
	 * Creates a new, voms-enabled Credential object from an arbitrary VO.
	 * 
	 * @param vo
	 *            the VO
	 * @param fqan
	 *            the fqan
	 * @param upload
	 *            whether to upload the voms proxy to myproxy
	 * @return the Credential
	 * @throws CredentialException
	 *             if the Credential can't be created (e.g. voms error).
	 */
	private Credential getVomsCredential(VO vo, String fqan, boolean upload)
			throws CredentialException {


		Credential c = children.get(fqan);
		if (c != null) {
			return c;
		}

		myLogger.debug("Credential " + uuid + ": no child credential for fqan "
				+ fqan + " found, creating new one.");

		Credential child = new WrappedGssCredential(getCredential(), vo, fqan);
		children.put(fqan, child);
		if (upload) {
			child.uploadMyProxy(getMyProxyServer(), getMyProxyPort(), true);
		}
		return child;
	}

	@Override
	public int hashCode() {

		try {
			return getCredential().hashCode() * 432;
		} catch (CredentialException e) {
			return uuid.hashCode();
		}
	}

	public boolean isSaved() {
		return isSaved;
	}

	public boolean isUploaded() {
		Boolean temp = (Boolean) getProperty(PROPERTY.Uploaded);
		if (temp == null) {
			return false;
		}
		return temp;
	}

	/**
	 * Checks whether this credential is valid.
	 * 
	 * @return true - if valid; false - if not
	 */
	public final boolean isValid() {
		try {
			if (getCredential() == null) {
				return false;
			}
			if (getCredential().getRemainingLifetime() <= 0) {
				return false;
			} else {
				return true;
			}
		} catch (final GSSException e) {
			myLogger.error(e.getLocalizedMessage(), e);
			return false;
		}
	}

	public synchronized boolean recreateGssCredential(
			Map<PROPERTY, Object> configNew) {

		myLogger.debug("Recreating credential " + uuid);

		lastCredentialAutoRefresh = new Date();

		Map<PROPERTY, Object> config = new HashMap<PROPERTY, Object>(
				getProperties());
		if (configNew != null) {
			config.putAll(configNew);
		}

		try {
			GSSCredential cred = this.cred;
			String dn = null;
			if (cred != null) {
				dn = CertHelpers.getDnInProperFormat(cred);
			}

			GSSCredential c = createGssCredential(config);
			if (StringUtils.isNotBlank(dn)) {
				if (!dn.equals(CertHelpers.getDnInProperFormat(c))) {
					myLogger.error("Can't refresh credential, dns don't match.");
					return false;
				}
			}
			setCredential(c);

			if (isUploaded()) {
				uploadMyProxy(null, -1, true);
			}

			for (String fqan : children.keySet()) {
				myLogger.debug("Credential " + uuid
						+ ": Refreshing child credential for fqan " + fqan);
				Credential child = children.get(fqan);
				GSSCredential vomsGSS = WrappedGssCredential
						.createVomsCredential(c,
								(VO) child.getProperty(PROPERTY.VO),
								fqan);
				child.setCredential(vomsGSS);
				if (child.isUploaded()) {
					child.uploadMyProxy(null, -1, true);
				}
			}
			if (isSaved()) {
				isSaved = false;
				saveCredential(getLocalPath());
			}


			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public boolean refresh() {

		myLogger.debug("Refreshing credential");

		boolean success = false;
		for (CredentialRefresher crui : refreshUI) {
			myLogger.debug("Credential "
					+ uuid
					+ ": Trying to refresh credential using refresher of class "
					+ crui.getClass().getSimpleName());
			try {
				success = crui.refresh(this);
				if (success) {
					break;
				}
			} catch (CredentialException e) {
				myLogger.error(
						"Refreshing credential failed: "
								+ e.getLocalizedMessage(), e);
			}
		}

		return success;

	}

	public void removeCredentialRefreshIUI(CredentialRefresher ui) {
		this.refreshUI.remove(ui);
	}

	public void removeProperty(PROPERTY key) {
		this.properties.remove(key);
	}

	public void saveCredential() throws CredentialException {
		saveCredential(null);
	}

	/**
	 * Saves this Credential to disk.
	 * 
	 * @param localPath
	 *            the path to write it to or null for default location (e.g.
	 *            /tmp/x509u... on Linux)
	 * @throws CredentialException
	 *             if the credential can't be written to disk for some reason.
	 */
	public void saveCredential(String localPath) throws CredentialException {

		myLogger.debug("Saving credential: " + uuid);

		if (StringUtils.isBlank(localPath)) {
			localPath = LocalProxy.PROXY_FILE;
		}
		addProperty(PROPERTY.LocalPath, localPath);

		CredentialHelpers.writeToDisk(getCredential(), new File(localPath));

		this.isSaved = true;

		saveCredentialMetadata();

	}

	private void saveCredentialMetadata() {

		myLogger.debug("Saving credential metadata: " + uuid);

		String localPath = (String) getProperty(PROPERTY.LocalPath);
		if (StringUtils.isBlank(localPath)) {
			throw new RuntimeException("No local path specified.");
		}

		File metadataFile = new File(localPath + "."
				+ METADATA_FILE_EXTENSION);

		Properties prop = new Properties();

		String thisFqan = getFqan();
		if (StringUtils.isNotBlank(thisFqan)) {
			properties.put(PROPERTY.FQAN, thisFqan);
		}

		if (new File(localPath).exists()) {
			String proxy = null;
			try {
				proxy = FileUtils.readFileToString(new File(localPath));
			} catch (IOException e1) {
				myLogger.error("Can't read proxy file " + localPath, e1);
			}
			String md5 = DigestUtils.md5Hex(proxy);
			properties.put(PROPERTY.md5sum, md5);
		}

		for (PROPERTY p : properties.keySet()) {

			switch (p) {
			case MyProxyPassword:
				prop.put(p.toString(), new String((char[]) properties.get(p)));
				break;
			default:
				prop.put(p.toString(), properties.get(p).toString());
			}

		}

		for (Credential child : children.values()) {
			if (!child.isUploaded()) {
				continue;
			}

			String fqan = child.getFqan();
			String myProxyUsername = child.getMyProxyUsername();
			char[] myProxyPassword = child.getMyProxyPassword();
			String myProxyHost = child.getMyProxyServer();
			int myProxyPort = child.getMyProxyPort();
			prop.put(CHILD_KEY + "." + fqan + "." + PROPERTY.MyProxyUsername,
					myProxyUsername);
			prop.put(CHILD_KEY + "." + fqan + "." + PROPERTY.MyProxyPassword,
					new String(myProxyPassword));
			prop.put(CHILD_KEY + "." + fqan + "." + PROPERTY.MyProxyHost,
					myProxyHost);
			prop.put(CHILD_KEY + "." + fqan + "." + PROPERTY.MyProxyPort,
					new Integer(myProxyPort).toString());

		}

		try {
			prop.store(new FileOutputStream(metadataFile), null);
			Util.setFilePermissions(metadataFile.getAbsolutePath(), 600);
		} catch (Exception e) {
			throw new RuntimeException("Can't store credential metadata.", e);
		}
	}

	private void setCredential(GSSCredential gss) {
		myLogger.debug("Credential " + uuid + ": Setting credential.");
		this.cred = gss;
		setGssCredential(gss);
	}

	protected abstract void setGssCredential(GSSCredential cred);

	public void setMinimumLifetime(int minLifetimeInSeconds) {
		this.minLifetimeInSeconds = minLifetimeInSeconds;
	}

	public void setMyProxyDelegatedPassword(char[] myProxyPassphrase) {
		setProperty(PROPERTY.MyProxyPassword, myProxyPassphrase);
	}

	public void setMyProxyDelegatedUsername(String myProxyUsername2) {
		setProperty(PROPERTY.MyProxyUsername, myProxyUsername2);
	}

	public void setProperty(PROPERTY p, Object value) {
		properties.put(p, value);
	}

	private void setSaved(boolean b) {
		this.isSaved = b;
	}

	// private void setUploaded(boolean b) {
	// this.uploaded = b;
	// }

	/**
	 * Uploads this credential to the default MyProxy host.
	 * 
	 * If this credential is created from a MyProxy username/password, the
	 * default MyProxy host is the one the original Credential was created from.
	 * Otherwise {@link #DEFAULT_MYPROXY_SERVER} is used.
	 * 
	 * @throws CredentialException
	 *             if the MyProxy credential can't be delegated.
	 */
	public void uploadMyProxy() throws CredentialException {
		uploadMyProxy(null, -1, false);
	}

	public void uploadMyProxy(boolean force) throws CredentialException {
		uploadMyProxy(null, -1, force);
	}

	/**
	 * Uploads this credential to MyProxy.
	 * 
	 * @param myProxyHostUp
	 *            the MyProxy host
	 * @param myProxyPortUp
	 *            the MyProxy port
	 * @throws CredentialException
	 *             if the MyProxy credential can't be delegated.
	 */
	public synchronized void uploadMyProxy(String myProxyHostUp,
			int myProxyPortUp, boolean force) throws CredentialException {

		myLogger.debug("Credential " + uuid + ": uploading to my proxy...");

		boolean uploadedTemp = isUploaded();
		if (force) {
			uploadedTemp = false;
		}

		if (uploadedTemp == true) {
			myLogger.debug("Credential " + uuid
					+ ": already uploaded and no force.");
			return;
		}

		if (StringUtils.isNotBlank(myProxyHostUp)) {
			setProperty(PROPERTY.MyProxyHost, myProxyHostUp);
		}

		if (myProxyPortUp > 0) {
			setProperty(PROPERTY.MyProxyPort, myProxyPortUp);
		}

		myLogger.debug("Uploading credential to: " + getMyProxyServer());

		MyProxy mp = MyProxy_light.getMyProxy(getMyProxyServer(),
				getMyProxyPort());

		InitParams params = null;
		try {
			params = MyProxy_light.prepareProxyParameters(getMyProxyUsername(),
					null, null, null, null, getInitialLifetime() + 3600);
		} catch (MyProxyException e) {
			throw new CredentialException("Can't prepare myproxy parameters", e);
		}

		try {
			MyProxy_light.init(mp, getCredential(), params,
					getMyProxyPassword());
			addProperty(PROPERTY.Uploaded, Boolean.TRUE);

		} catch (Exception e) {
			throw new CredentialException("Can't upload MyProxy", e);
		}

	}

}
