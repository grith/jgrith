package grith.jgrith.credential;

import gridpp.portal.voms.VOMSAttributeCertificate;
import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.credential.refreshers.CredentialRefresher;
import grith.jgrith.credential.refreshers.StaticCredentialRefresher;
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
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
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
		LoginType, Username, Password, MyProxyHost, MyProxyPort, VO, FQAN, EndDate, md5sum, SlcsUrl, IdP, CertFile, KeyFile
	}

	private class RemainingLifetimeReminder {

		private final CredentialListener l;
		private final int secondsBeforeExpiry;

		public RemainingLifetimeReminder(CredentialListener l,
				int secondsBeforeExpiry) {
			this.l = l;
			this.secondsBeforeExpiry = secondsBeforeExpiry;
		}

		public CredentialListener getCredentialListener() {
			return this.l;
		}

		public int getSecondsBeforeExpiry() {
			return this.secondsBeforeExpiry;
		}

		public TimerTask getTask() {
			return new TimerTask() {

				@Override
				public void run() {
					l.credentialAboutToExpire(Credential.this);
				}
			};
		}

	}

	public enum Type {
		Local, MyProxy, SLCS, Proxy
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

	public static final int DEFAULT_PROXY_LIFETIME_IN_HOURS = 24;

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

	private final StaticCredentialRefresher defaultCredentialRefresh = new StaticCredentialRefresher(
			false);

	private final List<CredentialRefresher> refreshUI = Lists
			.newArrayList((CredentialRefresher) defaultCredentialRefresh);

	private final boolean myproxyCredential = false;

	private boolean uploaded = false;

	private String myProxyHost = null;

	private int myProxyPort = -1;

	private String myProxyUsername;

	private char[] myProxyPassword;

	private String localPath = null;
	private final UUID uuid = UUID.randomUUID();

	private Map<String, VO> fqans;

	private Calendar endTime;

	private int minLifetimeInSeconds = 3600;

	private final List<RemainingLifetimeReminder> remainingLiftimeReminder = Lists
			.newLinkedList();

	private final Timer timer = new Timer("credentialExpiryTimer", true);

	private final Map<PROPERTY, Object> properties = Maps.newHashMap();

	private final Map<String, Credential> children = Maps.newConcurrentMap();

	private boolean isSaved = false;
	public void addCredentialRefreshIUI(CredentialRefresher ui) {
		this.refreshUI.add(ui);
	}

	public void addProperty(PROPERTY key, Object value) {
		this.properties.put(key, value);
	}


	/**
	 * Calls the {@link CredentialListener#credentialAboutToExpire(Credential)}
	 * method of the listener xx seconds before this credential expires.
	 * 
	 * @param l
	 *            the listener
	 * @param secondsBeforeExpiry
	 *            the min time until this credential expires. if this is bigger
	 *            than the credential lifetime, the method will be called after
	 *            1 second straight away...
	 */
	public void addRemainingLifetimeReminder(final CredentialListener l,
			final int secondsBeforeExpiry) {

		int remainingLifetime = getRemainingLifetime();
		int wait = remainingLifetime - secondsBeforeExpiry;
		if (wait <= 0) {
			wait = 1;
		}

		RemainingLifetimeReminder er = new RemainingLifetimeReminder(l,
				secondsBeforeExpiry);
		remainingLiftimeReminder.add(er);
		timer.schedule(er.getTask(), wait * 1000);

	}

	public boolean autorefresh() {

		try {
			int oldLt = getGSSCredential().getRemainingLifetime();
			defaultCredentialRefresh.refresh(this);
			int newLt = getGSSCredential().getRemainingLifetime();
			if (oldLt >= newLt) {
				return false;
			} else {
				return true;
			}
		} catch (Exception e) {
			return false;
		}

	}

	public abstract void createGssCredential(Map<PROPERTY, Object> config)
			throws CredentialException;

	/**
	 * Destroys proxy and possibly metadata file
	 */
	public void destroy() {

		destroyCredential();

		try {
			getGSSCredential().dispose();
		} catch (Exception e) {
			// that's ok
		}

		if (StringUtils.isNotBlank(localPath)) {
			if (new File(localPath).exists()) {
				myLogger.debug("Deleting proxy file " + localPath);
				Util.destroy(localPath);
			}
		}

		if (uploaded) {

			myLogger.debug("Destrying uploaded proxy from host: " + myProxyHost);
			MyProxy mp = new MyProxy(myProxyHost, myProxyPort);
			try {
				mp.destroy(getGSSCredential(), myProxyUsername, new String(
						myProxyPassword));
			} catch (MyProxyException e) {
				myLogger.error("Can't destroy myproxy credential.", e);
			}

			Arrays.fill(myProxyPassword, 'x');
		}

	}

	public abstract void destroyCredential();

	@Override
	public boolean equals(Object o) {
		if (o instanceof Credential) {
			Credential other = (Credential) o;
			if (myproxyCredential) {
				if (myProxyUsername.equals(other.getMyProxyUsername())
						&& Arrays.equals(myProxyPassword,
								other.getMyProxyPassword())) {
					return true;
				} else {
					return false;
				}
			} else {
				try {
					return getGSSCredential().equals(
							((Credential) o).getGSSCredential());
				} catch (CredentialException e) {
					return false;
				}
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
			if (remaining < minLifetimeInSeconds) {

				autorefresh();

				getGSSCredential().getRemainingLifetime();

				if (!isValid()) {
					throw new InvalidCredentialException("Credential expired.");
				}
			}
		} catch (GSSException e) {
			throw new InvalidCredentialException(e);
		}
		return c;

	}

	public StaticCredentialRefresher getDefaultRefresher() {
		return defaultCredentialRefresh;

	}

	public String getDn() {
		return CertHelpers.getDnInProperFormat(getCredential());
	}

	public Calendar getEndDate() {
		if (this.endTime == null) {
			endTime = Calendar.getInstance();
			endTime.add(Calendar.SECOND, getRemainingLifetime());
			properties.put(PROPERTY.EndDate, endTime.getTimeInMillis());
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

	protected abstract GSSCredential getGSSCredential()
			throws CredentialException;

	public String getLocalPath() {

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

		if (myProxyPassword == null) {
			myProxyPassword = new RandPass().getPassChars(10);
		}
		return myProxyPassword;
	}

	public int getMyProxyPort() {
		return this.myProxyPort;
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
		return myProxyHost;
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

		if (myproxyCredential) {
			return myProxyUsername;
		} else {
			if (StringUtils.isNotBlank(myProxyUsername)) {
				return myProxyUsername;
			} else {
				myProxyUsername = UUID.randomUUID().toString();
				// }
				return myProxyUsername;
			}

		}
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

		Credential child = new WrappedGssCredential(getCredential(), vo, fqan);
		children.put(fqan, child);
		if (upload) {
			child.uploadMyProxy(myProxyHost, myProxyPort);
		}
		return child;
	}

	@Override
	public int hashCode() {
		if (myproxyCredential) {
			return (myProxyPassword.hashCode() + myProxyPassword.hashCode()) * 32;
		} else {
			try {
				return getCredential().hashCode() * 432;
			} catch (CredentialException e) {
				return uuid.hashCode();
			}
		}
	}

	// private void initProperties(Properties p, String group, boolean check) {
	// Map<String, Properties> childs = Maps.newHashMap();
	//
	// for (Enumeration<?> keys = p.propertyNames(); keys
	// .hasMoreElements();) {
	// String key = (String) keys.nextElement();
	// try {
	// PROPERTY prop = PROPERTY.valueOf(key);
	// properties.put(prop, p.get(key));
	// } catch (IllegalArgumentException iae) {
	//
	// // means it is not a property, probably child
	// if (!key.startsWith(CHILD_KEY)) {
	// myLogger.debug("Ignoring property "+key+"...");
	// continue;
	// }
	//
	// String[] tokens = key.split("\\.");
	//
	// String fqan = tokens[1];
	// String property = tokens[2];
	// String value = p.getProperty(key);
	// Properties ptemp = childs.get(fqan);
	// if (ptemp == null) {
	// ptemp = new Properties();
	// childs.put(fqan, ptemp);
	// }
	// ptemp.put(property, value);
	//
	// }
	// }
	//
	// boolean origMyProxy = LoginType.MYPROXY.equals(properties
	// .get(PROPERTY.LoginType));
	//
	// for (PROPERTY pr : properties.keySet()) {
	// switch (pr) {
	// case MyProxyUsername:
	// myProxyUsername = (String) properties.get(pr);
	// break;
	// case MyProxyPassword:
	// myProxyPassword = ((String) properties.get(pr)).toCharArray();
	// uploaded = true;
	// break;
	// case MyProxyHost:
	// if (origMyProxy) {
	// myProxyHost = (String) properties.get(pr);
	// }
	// myProxyHost = (String) properties.get(pr);
	// break;
	// case MyProxyPort:
	// if (origMyProxy) {
	// myProxyPort = Integer.parseInt((String) properties
	// .get(pr));
	// }
	// myProxyPort = Integer.parseInt((String) properties.get(pr));
	// break;
	// }
	// }
	//
	// if (check) {
	// try {
	// getCredential().getRemainingLifetime();
	// } catch (Exception e) {
	// throw new CredentialException(
	// "Can't retrieve credential from MyProxy.", e);
	// }
	// }
	//
	//
	//
	// for (String fqan : childs.keySet()) {
	// Credential c = new Credential(childs.get(fqan), fqan, check);
	// children.put(fqan, c);
	// }
	//
	// for (PROPERTY pr : properties.keySet()) {
	// System.out.println("PROPERTY: " + pr + ": " + properties.get(pr));
	// }
	//
	// for (String fqan : childs.keySet()) {
	// System.out.println("Child " + fqan);
	// Properties ptemp = childs.get(fqan);
	// for (Object key : ptemp.keySet()) {
	// System.out.println("\t" + key.toString() + " - "
	// + ptemp.getProperty((String) key).toString());
	// }
	// }
	// }

	public boolean isSaved() {
		return isSaved;
	}

	public boolean isUploaded() {
		return this.uploaded;
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

	public boolean refresh() {
		for (CredentialRefresher crui : refreshUI) {
			try {
				crui.refresh(this);

				if (uploaded) {
					uploadMyProxy(null, -1);
				}

				return true;
			} catch (CredentialException e) {
				myLogger.error(
						"Refreshing credential failed: "
								+ e.getLocalizedMessage(), e);
			}
		}
		return false;
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

		if (StringUtils.isBlank(localPath)) {
			localPath = LocalProxy.PROXY_FILE;
		}
		CredentialHelpers.writeToDisk(getCredential(), new File(localPath));

		this.localPath = localPath;
		this.isSaved = true;

		if (uploaded) {
			saveCredentialMetadata();
		} else {
			boolean save = false;
			for (Credential c : children.values()) {
				if (c.isUploaded()) {
					save = true;
				}
			}
			if (save) {
				saveCredentialMetadata();
			}
		}
	}

	private void saveCredentialMetadata() {
		if (this.localPath == null) {
			throw new RuntimeException("No local path specified.");
		}

		File metadataFile = new File(this.localPath + "."
				+ METADATA_FILE_EXTENSION);

		Properties prop = new Properties();

		String thisFqan = getFqan();
		if (StringUtils.isNotBlank(thisFqan)) {
			properties.put(PROPERTY.FQAN, thisFqan);
		}

		if (new File(localPath).exists()) {
			String proxy = null;
			try {
				proxy = FileUtils.readFileToString(new File(this.localPath));
			} catch (IOException e1) {
				myLogger.error("Can't read proxy file " + localPath, e1);
			}
			String md5 = DigestUtils.md5Hex(proxy);
			properties.put(PROPERTY.md5sum, md5);
		}

		for (PROPERTY p : properties.keySet()) {
			prop.put(p.toString(), properties.get(p).toString());
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
			prop.put(CHILD_KEY + "." + fqan + "." + PROPERTY.Username,
					myProxyUsername);
			prop.put(CHILD_KEY + "." + fqan + "." + PROPERTY.Password,
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

	public void setMinimumLifetime(int minLifetimeInSeconds) {
		this.minLifetimeInSeconds = minLifetimeInSeconds;
	}

	public void setMyProxyDelegatedPassword(char[] myProxyPassphrase) {
		this.myProxyPassword = myProxyPassphrase;
	}

	public void setMyProxyDelegatedUsername(String myProxyUsername2) {
		this.myProxyUsername = myProxyUsername2;
	}

	public void setProperty(PROPERTY p, Object value) {
		properties.put(p, value);
	}

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
		uploadMyProxy(null, -1);
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
			int myProxyPortUp) throws CredentialException {

		if (uploaded == true) {
			return;
		}

		if (StringUtils.isNotBlank(myProxyHostUp)) {
			this.myProxyHost = myProxyHostUp;
		} else {
			if (StringUtils.isBlank(this.myProxyHost)) {
				this.myProxyHost = DEFAULT_MYPROXY_SERVER;
			}
		}

		if (myProxyPortUp > 0) {
			this.myProxyPort = myProxyPortUp;
		} else {
			if (this.myProxyPort < 0) {
				this.myProxyPort = DEFAULT_MYPROXY_PORT;
			}
		}

		myLogger.debug("Uploading credential to: " + myProxyHost);

		MyProxy mp = MyProxy_light.getMyProxy(myProxyHost, myProxyPort);

		InitParams params = null;
		try {
			params = MyProxy_light.prepareProxyParameters(getMyProxyUsername(),
					null, null, null, null, getRemainingLifetime());
		} catch (MyProxyException e) {
			throw new CredentialException("Can't prepare myproxy parameters", e);
		}

		try {
			MyProxy_light.init(mp, getCredential(), params,
					getMyProxyPassword());
			uploaded = true;
			properties.put(PROPERTY.Username, getMyProxyUsername());
			properties.put(PROPERTY.Password, new String(
					getMyProxyPassword()));
			properties.put(PROPERTY.MyProxyHost, myProxyHost);
			properties.put(PROPERTY.MyProxyPort, new Integer(myProxyPort));
		} catch (Exception e) {
			throw new CredentialException("Can't upload MyProxy", e);
		}

	}

}
