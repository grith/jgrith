package grith.jgrith.cred;

import grisu.jcommons.configuration.CommonGridProperties;
import grisu.jcommons.constants.Constants;
import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.exceptions.CredentialException;
import grisu.model.info.dto.VO;
import grith.jgrith.cred.callbacks.AbstractCallback;
import grith.jgrith.cred.callbacks.CliCallback;
import grith.jgrith.cred.callbacks.NoCallback;
import grith.jgrith.cred.details.CredDetail;
import grith.jgrith.cred.details.LoginTypeDetail;
import grith.jgrith.credential.Credential.PROPERTY;
import grith.jgrith.myProxy.MyProxy_light;
import grith.jgrith.utils.CertHelpers;
import grith.jgrith.utils.CredentialHelpers;
import grith.jgrith.voms.VOManagement.VOManagement;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.File;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.globus.common.CoGProperties;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.globus.util.Util;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

public abstract class AbstractCred extends BaseCred implements Cred {

	class CredentialInvalid extends TimerTask {

		@Override
		public void run() {
			myLogger.debug("Credential invalid now");
			pcs.firePropertyChange("valid", true, false);
		}
	}

	class CredentialMinThreshold extends TimerTask {

		@Override
		public void run() {
			myLogger.debug("Min threshold reached");
			pcs.firePropertyChange("belowMinLifetime", false, true);
		}
	}

	class CredentialRenewTask extends TimerTask {
		@Override
		public void run() {
			myLogger.debug("Auto renew task started.");
			refresh();
		}
	}

	static final Logger myLogger = LoggerFactory.getLogger(AbstractCred.class
			.getName());

	public static AbstractCred create(AbstractCallback callback) {
		return loadFromConfig(null, callback);
	}

	public static AbstractCred loadFromConfig(Map<PROPERTY, Object> config) {
		return loadFromConfig(config, null);
	}

	public static AbstractCred loadFromConfig(Map<PROPERTY, Object> config,
			AbstractCallback callback) {

		if (config == null) {
			config = Maps.newHashMap();
		}

		myLogger.debug("Loading credential from config map...");

		try {
			LoginType type = null;
			try {
				type = (LoginType) config.get(PROPERTY.LoginType);
			} catch (Exception e) {
				myLogger.debug("Can't get login type...");
			}

			if ((type == null) && (callback != null)) {
				CredDetail<String> lt = new LoginTypeDetail();
				callback.fill(lt);
				String input = lt.getValue();
				if (StringUtils.isBlank(input)) {
					throw new CredentialException("No login type specified.");
				} else if (input.contains("Institution login")) {
					if (input.contains("using:")) {
						type = LoginType.SHIBBOLETH_LAST_IDP;
					} else {
						type = LoginType.SHIBBOLETH;
					}
				} else if (input.equals("Certificate login")) {
					type = LoginType.X509_CERTIFICATE;
				} else if (input.equals("MyProxy login")) {
					type = LoginType.MYPROXY;
				}

			}

			if (type == null) {
				throw new CredentialException("No credential type specified.");
			}

			AbstractCred c = null;
			switch (type) {
			case MYPROXY:
				c = new MyProxyCred();
				break;
			case SHIBBOLETH_LAST_IDP:
				String idp = CommonGridProperties.getDefault().getLastShibIdp();
				config.put(PROPERTY.IdP, idp);
			case SHIBBOLETH:
				c = new SLCSCred();
				break;
			case X509_CERTIFICATE:
				c = new X509Cred();
				break;
			default:
				throw new CredentialException("Login type " + type.toString()
						+ " not supported.");
			}
			if (callback != null) {
				c.setCallback(callback);
			}

			c.init(config);
			return c;
		} catch (CredentialException ce) {
			throw ce;
		} catch (Exception e) {
			e.printStackTrace();
			throw new CredentialException("Can't create credential: "
					+ e.getLocalizedMessage(), e);
		}

	}

	public static void main(String[] args) throws Exception {

		SLCSCred x = new SLCSCred();
		x.setCallback(new CliCallback());
		x.init();

		System.out.println(x.getGSSCredential().getName().toString());

		x.uploadMyProxy(false);

		x.saveMyProxy();

		MyProxyCred mp = new MyProxyCred();
		mp.initFromFile();

		System.out.println(mp.getRemainingLifetimeMyProxy());

	}

	private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);

	private long minTimeBetweenAutoRefreshes = 100;

	protected boolean isUploaded = false;

	protected boolean isPopulated = false;

	protected int proxyLifetimeInSeconds = 864000;

	protected AbstractCallback credCallback = new NoCallback();

	private GSSCredential cachedCredential = null;

	protected String localPath;

	private Map<String, AbstractCred> groupCache = Maps.newHashMap();

	private Map<String, String> groupPathCache = Maps.newHashMap();

	private Map<String, VO> fqans;

	private int minProxyLifetime = DEFAULT_MIN_LIFETIME_IN_SECONDS;

	private CredentialInvalid invalidTask = null;

	private CredentialMinThreshold minThresholdTask = null;

	private CredentialRenewTask renewTask = null;
	private final Timer timer = new Timer(true);

	private volatile Date lastCredentialAutoRefresh = new Date();

	public AbstractCred() {
		super();
	}

	public AbstractCred(AbstractCallback callback) {
		super();
		setCallback(callback);
	}

	public AbstractCred(AbstractCallback callback, Map<PROPERTY, Object> config) {
		super(config);
		init(callback, config);
	}

	/**
	 * Constructor to create a credential out of a provided config map.
	 *
	 * All credential properties need to be set, otherwise an error will be
	 * thrown. No Callback is set.
	 *
	 * @param config
	 *            the credential properties
	 */
	public AbstractCred(Map<PROPERTY, Object> config) {
		super(config);
		init(config);
	}

	public AbstractCred(String mpUsername, char[] mpPassword, String mpHost,
			int mpPort) {
		super(mpUsername, mpPassword, mpHost, mpPort);
	}

	public void addPropertyChangeListener(PropertyChangeListener l) {
		pcs.addPropertyChangeListener(l);
	}

	public synchronized void createGSSCredential() {

		cachedCredential = createGSSCredentialInstance();

		lastCredentialAutoRefresh = new Date();

		groupCache.clear();

		Thread t1 = new Thread() {
			@Override
			public void run() {

				if (isUploaded) {
					uploadMyProxy(true);
				}
			}
		};
		t1.setName("MyProxyUpdateThread");
		t1.start();

		Thread t2 = new Thread() {
			@Override
			public void run() {

				if (StringUtils.isNotBlank(localPath)) {
					saveProxy(localPath);
				}

				for (String group : groupPathCache.keySet()) {
					String path = groupPathCache.get(group);
					saveGroupProxy(group, path);
				}
			}
		};
		t2.setName("Proxy save thread");
		t2.start();

		Thread t3 = new Thread() {
			@Override
			public void run() {
				for (String group : groupCache.keySet()) {

					AbstractCred cred = groupCache.get(group);
					if ( cred instanceof GroupCred ) {
						myLogger.debug("not updating myproxy for group "+group);
						return;
					}
					myLogger.debug("updating group cred: " + group);
					GroupCred gc = (GroupCred)cred;
					gc.setBaseCred(AbstractCred.this);

				}
			}
		};
		t3.setName("MyProxyGroupUpdateThread");
		t3.start();

		int remaining = -1;
		try {
			remaining = cachedCredential.getRemainingLifetime();
		} catch (GSSException e) {
			throw new CredentialException("Can't get remaining lifetime.", e);
		}
		if (invalidTask != null) {
			invalidTask.cancel();
		}

		if (minThresholdTask != null) {
			minThresholdTask.cancel();
		}

		if (renewTask != null) {
			renewTask.cancel();
		}

		invalidTask = new CredentialInvalid();
		timer.schedule(invalidTask, remaining * 1000);
		minThresholdTask = new CredentialMinThreshold();
		int delay = remaining - getMinimumLifetime();
		if (delay < 0) {
			delay = 0;
		}

		if (delay > 0) {
			timer.schedule(minThresholdTask, delay * 1000);
		}

		// try to renew before minThreshold is there
		renewTask = new CredentialRenewTask();
		delay = delay - 20;
		if (delay > 0) {
			timer.schedule(renewTask, delay * 1000);
		}

	}

	abstract public GSSCredential createGSSCredentialInstance();

	/* (non-Javadoc)
	 * @see grith.jgrith.cred.Cred#destroy()
	 */
	@Override
	public void destroy() {
		if ( cachedCredential != null ) {

			new Thread() {
				@Override
				public void run() {

					if (cachedCredential != null) {

						if (isUploaded) {
							try {
								myLogger.debug("Destrying uploaded proxy from host: "
										+ getMyProxyHost());
								MyProxy mp = new MyProxy(getMyProxyHost(),
										getMyProxyPort());
								try {
									mp.destroy(cachedCredential,
											getMyProxyUsername(), new String(
													getMyProxyPassword()));
								} catch (MyProxyException e) {
									myLogger.error(
											"Can't destroy myproxy credential.",
											e);
								}
							} catch (Exception e) {
								myLogger.debug(
										"Error when trying to destroy myproxy cred.",
										e);
							}
						}
						try {
							cachedCredential.dispose();
						} catch (GSSException e) {
							myLogger.debug(
									"Error when disposing gsscredential.", e);
						}

					}
				}
			}.start();

		}

		for (AbstractCred cred : groupCache.values()) {
			try {
				// for non-vo cred this would result in a loop otherwise
				if (cred instanceof GroupCred) {
					cred.destroy();
				}
			} catch (Exception e) {
				myLogger.debug("Error when disposing group gss credential.");
			}
		}

		for (String path : groupPathCache.values()) {
			Util.destroy(path);
		}

		if (StringUtils.isNotBlank(this.localPath)) {
			if (new File(localPath).exists()) {
				myLogger.debug("Deleting proxy file " + localPath);
				Util.destroy(localPath);
			}
		}

		destroyMyProxy();
	}

	/**
	 * Get a map of all Fqans (and VOs) the user has access to.
	 *
	 * @return the Fqans of the user
	 */
	public synchronized Map<String, VO> getAvailableFqans() {

		if (fqans == null) {
			fqans = VOManagement.getAllFqans(getGSSCredential());
		}
		return fqans;

	}

	private AbstractCallback getCallback() {
		if (credCallback == null) {
			throw new CredentialException(
					"No callback configured for credential.");
		}
		return credCallback;
	}

	/* (non-Javadoc)
	 * @see grith.jgrith.cred.Cred#getDN()
	 */
	@Override
	public String getDN() {
		return CertHelpers.getDnInProperFormat(getGSSCredential());
	}

	public AbstractCred getGroupCredential(String fqan) {

		synchronized (fqan) {

			if (StringUtils.isBlank(fqan)) {
				fqan = Constants.NON_VO_FQAN;
			}

			AbstractCred temp = groupCache.get(fqan);
			if (temp == null) {
				myLogger.debug("creating GroupCred for: " + fqan);
				if (StringUtils.isBlank(fqan) || Constants.NON_VO_FQAN.equals(fqan)) {
					AbstractCred groupCred = this;
					groupCache.put(fqan, groupCred);
				} else {

					VO vo = getAvailableFqans().get(fqan);
					if (vo == null) {
						throw new CredentialException("Can't find VO for fqan: " + fqan);
					} else {
						GroupCred groupCred = getGroupCredential(vo, fqan);
						groupCache.put(fqan, groupCred);
					}
				}
			}
		}

		return groupCache.get(fqan);

	}
	
	public void setSaveDetails(boolean save) {
		
		for ( CredDetail d : getDetails() ) {
			d.setSaveToPropertiesFile(save);
		}
		
	}
	
	public String getFqan() {
		
		if ( this instanceof GroupCred ) {
			return ((GroupCred)this).getFqan();
		} else {
			return Constants.NON_VO_FQAN;
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
	private GroupCred getGroupCredential(VO vo, String fqan)
			throws CredentialException {

		if (VO.NON_VO.equals(vo)) {
			throw new CredentialException("No valid VO specified.");
		}

		try {
			GroupCred gc = new GroupCred(this, vo, fqan);
			return gc;
		} catch (Exception e) {
			throw new CredentialException("Can't create VOMS proxy: "
					+ e.getLocalizedMessage(), e);
		}

	}

	public String getGroupProxyPath(String group) {
		return groupPathCache.get(group);
	}

	public Set<String> getGroups() {

		return getAvailableFqans().keySet();

	}

	public GSSCredential getGSSCredential() {

		try {
			if ((cachedCredential == null) ) {
				if (!isPopulated) {
					throw new CredentialException(
							"Credential not populated (yet).");
				}
				createGSSCredential();
				return cachedCredential;
			} else if ((cachedCredential.getRemainingLifetime() < minProxyLifetime)
					&& isRenewable()) {

				myLogger.debug(
						"Credential ({}) below min lifetime ({}). Trying to refresh...",
						cachedCredential.getRemainingLifetime(),
						minProxyLifetime);

				if (!isPopulated) {
					throw new CredentialException(
							"Credential not populated (yet).");
				}

				Date now = new Date();
				long diff = (now.getTime() - lastCredentialAutoRefresh
						.getTime()) / 1000;

				if ((diff > minTimeBetweenAutoRefreshes)) {
					refresh();
					lastCredentialAutoRefresh = new Date();
				} else {
					myLogger.debug(
							"Not refreshing credential since only {} secs since last refresh.",
							diff);
				}
				return cachedCredential;
			} else {
				return cachedCredential;
			}
		} catch (GSSException e) {
			throw new CredentialException(
					"Could not get remaining lifetime of credential.", e);
		}
	}

	public int getMinimumLifetime() {
		return this.minProxyLifetime;
	}

	protected int getProxyLifetimeInSeconds() {
		return proxyLifetimeInSeconds;
	}

	public String getProxyPath() {

		if (StringUtils.isNotBlank(this.localPath)
				&& new File(this.localPath).exists()) {
			return this.localPath;
		}
		return null;

	}

	/* (non-Javadoc)
	 * @see grith.jgrith.cred.Cred#getRemainingLifetime()
	 */
	@Override
	public int getRemainingLifetime() {
		try {
			return getGSSCredential().getRemainingLifetime();
		} catch (GSSException e) {
			throw new CredentialException("Can't get remaining lifetime.", e);
		} catch (CredentialException ce) {
			myLogger.debug("Can't get gsscredential.", ce);
			return 0;
		}
	}

	public synchronized void init() {
		init(new HashMap<PROPERTY, Object>());
	}

	public synchronized void init(AbstractCallback callback) {
		setCallback(callback);
		init();
	}

	public synchronized void init(AbstractCallback callback, Map<PROPERTY, Object> config) {
		setCallback(callback);
		init(config);
	}

	@Override
	public synchronized void init(Map<PROPERTY, Object> config) {
		isPopulated = false;
		isUploaded = false;

		cachedCredential = null;

		groupCache.clear();
		groupPathCache.clear();
		fqans = null;
		localPath = null;

		if (invalidTask != null) {
			invalidTask.cancel();
		}

		if (minThresholdTask != null) {
			minThresholdTask.cancel();
		}

		if (renewTask != null) {
			renewTask.cancel();
		}

		// just so that doesn't need to be configured for every Cred that
		// inherits this
		Object mph = config.get(PROPERTY.MyProxyHost);
		if ( (mph != null) && StringUtils.isNotBlank((String)mph) ) {
			setMyProxyHost((String) mph);
		}

		initCred(config);

		populate();

	}

	protected abstract void initCred(Map<PROPERTY, Object> config);

	@Override
	abstract public boolean isRenewable();

	public boolean isUploaded() {
		return isUploaded;
	}

	/* (non-Javadoc)
	 * @see grith.jgrith.cred.Cred#isValid()
	 */
	@Override
	public boolean isValid() {
		return (getRemainingLifetime() > 0);
	}
	
	private Set<CredDetail> getDetails() {
		
		Set<CredDetail> details = Sets.newLinkedHashSet();
		
		for (Field f : this.getClass().getDeclaredFields()) {
			myLogger.debug("populating field: {}", f);
			try {
				Class c = f.get(this).getClass().getSuperclass();
				if (CredDetail.class.equals(c)) {
					CredDetail d = (CredDetail) f.get(this);
					details.add(d);
				}
			} catch (Exception e) {
				myLogger.debug("Error when trying to get field: {}, {}", f,
						e.getLocalizedMessage());
			}
		}
		return details;
		
	}

	private void populate() {

		if (!isPopulated) {
			for ( CredDetail d : getDetails() ) {
				if (d.isSet()) {
					myLogger.debug("detail {} already set", d.getName());
				} else {
					myLogger.debug(
							"detail {} not set, calling callback...",
							d.getName());
					getCallback().fill(d);
					if (!d.isSet()) {
						myLogger.debug(
								"detail {} still not set, callback failed...",
								d.getName());
						throw new CredentialException(d.getName()
								+ " not filled");
					}
				}

			}

			createGSSCredential();

			isPopulated = true;
		}
		return;

	}

	@Override
	public synchronized boolean refresh() {

		if (!isRenewable()) {
			return false;
		}

		int lt = getRemainingLifetime();

		createGSSCredential();

		int newLt = getRemainingLifetime();

		return (newLt > lt);

	}

	public void removePropertyChangeListener(PropertyChangeListener l) {
		pcs.addPropertyChangeListener(l);
	}

	public void saveGroupProxy(String group) {
		saveGroupProxy(group, null);
	}

	public void saveGroupProxy(String group, String path) {
		synchronized (group) {
			if (StringUtils.isBlank(path)) {
				String temp = getProxyPath();
				if (StringUtils.isBlank(getProxyPath())) {
					temp = CoGProperties.getDefault().getProxyFile();
				}
				path = temp + group.replaceAll("/", "_");
			}

			if (StringUtils.equals(path, getProxyPath())) {
				this.localPath = null;
			}

			AbstractCred temp = getGroupCredential(group);

			CredentialHelpers.writeToDisk(temp.getGSSCredential(), new File(
					path));
			groupPathCache.put(group, path);
		}
	}

	@Override
	public String saveProxy() {
		return saveProxy(null);
	}

	@Override
	public String saveProxy(String path) {

		if (StringUtils.isBlank(path) && StringUtils.isNotBlank(this.localPath)) {
			path = this.localPath;
		} else if (StringUtils.isBlank(path)) {
			path = CoGProperties.getDefault().getProxyFile();
		}
		synchronized (path) {

			this.localPath = path;

			CredentialHelpers.writeToDisk(getGSSCredential(), new File(localPath));
			if (isUploaded()) {
				saveMyProxy(path);
			} else {
				FileUtils.deleteQuietly(new File(path
						+ DEFAULT_MYPROXY_FILE_EXTENSION));
			}
		}

		return localPath;

	}

	public void setCallback(AbstractCallback callback) {
		this.credCallback = callback;
	}

	@Override
	public void setMinimumLifetime(int m) {
		this.minProxyLifetime = m;

		if (minThresholdTask != null) {
			minThresholdTask.cancel();
		}

		if (renewTask != null) {
			renewTask.cancel();
		}

		minThresholdTask = new CredentialMinThreshold();
		int delay = getRemainingLifetime() - this.minProxyLifetime;
		if (delay < 0) {
			delay = 0;
		}

		timer.schedule(minThresholdTask, delay * 1000);

		// try to renew before minThreshold is there
		renewTask = new CredentialRenewTask();
		delay = delay - 20;
		if (delay > 0) {
			timer.schedule(renewTask, delay * 1000);
		}

	}

	@Override
	public void setMyProxyHost(String mph) {
		if (!StringUtils.equals(getMyProxyHost(), mph)) {
			super.setMyProxyHost(mph);
			isUploaded = false;
		}
	}

	@Override
	public void setMyProxyPassword(char[] pw) {
		if (!Arrays.equals(getMyProxyPassword(), pw)) {
			super.setMyProxyPassword(pw);
			isUploaded = false;
		}
	}

	@Override
	public void setMyProxyPort(int port) {
		if (port != getMyProxyPort()) {

			super.setMyProxyPort(port);
			isUploaded = false;
		}
	}

	@Override
	public void setMyProxyUsername(String username) {
		String tmpHost = extractMyProxyServerFromUsername(username);
		String tmpUsername = null;
		if (StringUtils.isNotBlank(tmpHost)) {
			tmpUsername = extractUsernameFromUsername(username);
			setMyProxyHost(tmpHost);
			setMyProxyUsername(tmpUsername);
		}

		if (!StringUtils.equals(getMyProxyUsername(), username)) {
			super.setMyProxyUsername(username);
			isUploaded = false;
		}
	}

	public void setProxyLifetimeInSeconds(int p) {
		this.proxyLifetimeInSeconds = p;
	}

	@Override
	public void uploadMyProxy() {
		uploadMyProxy(false);
	}

	/* (non-Javadoc)
	 * @see grith.jgrith.cred.Cred#uploadMyProxy(boolean)
	 */
	public synchronized void uploadMyProxy(boolean force) {

		if (!isPopulated) {
			init();
		}

		if ((cachedCredential == null)) {
			throw new CredentialException("Credential not populated (yet).");
		}

		myLogger.debug("Credential " + super.getMyProxyUsername()
				+ ": uploading to my proxy host '" + super.getMyProxyHost()
				+ "'...");

		if (force) {
			isUploaded = false;
		}

		// try {
		// if (cachedCredential.getRemainingLifetime() < minProxyLifetime) {
		// createGSSCredential();
		// groupCache.clear();
		// groupPathCache.clear();
		// isUploaded = false;
		// }
		// } catch (GSSException e1) {
		// throw new CredentialException(
		// "Can't get lifetime when trying to upload proxy.", e1);
		// }

		if (isUploaded == true) {
			myLogger.debug("Credential " + super.getMyProxyUsername()
					+ ": already uploaded and no force.");
			return;
		}

		MyProxy mp = MyProxy_light.getMyProxy(super.getMyProxyHost(),
				super.getMyProxyPort());

		InitParams params = null;
		try {
			params = MyProxy_light.prepareProxyParameters(getMyProxyUsername(),
					null, null, null, null,
					cachedCredential.getRemainingLifetime());
		} catch (MyProxyException e) {
			throw new CredentialException("Can't prepare myproxy parameters", e);
		} catch (GSSException e) {
			throw new CredentialException("Can't set proxy lifetime", e);
		}

		try {
			MyProxy_light.init(mp, cachedCredential, params,
					getMyProxyPassword());
			isUploaded = true;
			// invalidateCachedCredential();

		} catch (Exception e) {
			throw new CredentialException("Can't upload MyProxy: "
					+ e.getLocalizedMessage(), e);
		}

		if (StringUtils.isNotBlank(this.localPath)) {
			saveProxy();
		}
	}

}
