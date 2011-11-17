package grith.jgrith;

import grisu.jcommons.configuration.CommonGridProperties;
import grisu.jcommons.constants.Constants;
import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.exceptions.CredentialException;
import grisu.jcommons.utils.CliHelpers;
import grith.gsindl.SLCS;
import grith.jgrith.control.SlcsLoginWrapper;
import grith.jgrith.myProxy.MyProxy_light;
import grith.jgrith.plainProxy.LocalProxy;
import grith.jgrith.plainProxy.PlainProxy;
import grith.jgrith.utils.CliLogin;
import grith.jgrith.voms.VO;
import grith.jgrith.voms.VOManagement.VOManagement;
import grith.jgrith.vomsProxy.VomsProxy;
import grith.sibboleth.CredentialManager;
import grith.sibboleth.IdpObject;
import grith.sibboleth.StaticCredentialManager;
import grith.sibboleth.StaticIdpObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.globus.common.CoGProperties;
import org.globus.myproxy.DestroyParams;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.globus.util.Util;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.python.google.common.collect.Lists;
import org.python.google.common.collect.Maps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.Ostermiller.util.RandPass;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

/**
 * A wrapper class that wraps a {@link GSSCredential} and provides convenience
 * constructors and methods, like MyProxy- and VOMS-access and state management.
 * 
 * @author Markus Binsteiner
 * 
 */
public class Credential {

	private class ExpiryReminder {

		private final CredentialListener l;
		private final int secondsBeforeExpiry;

		public ExpiryReminder(CredentialListener l, int secondsBeforeExpiry) {
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

	public enum PROPERTY {
		LoginType,
		MyProxyUsername,
		MyProxyPassword,
		MyProxyHost,
		MyProxyPort,
		VO,
		FQAN,
		EndDate,
		md5sum
	}

	static final Logger myLogger = LoggerFactory.getLogger(Credential.class
			.getName());

	public final static String DEFAULT_MYPROXY_SERVER = GridEnvironment
			.getDefaultMyProxyServer();

	public final static int DEFAULT_MYPROXY_PORT = GridEnvironment
			.getDefaultMyProxyPort();
	public final static int DEFAULT_PROXY_LIFETIME_IN_HOURS = 12;

	public final static int MIN_REMAINING_LIFETIME = 600;

	public static final String METADATA_FILE_EXTENSION = "md";

	public static final String CHILD_KEY = "group";

	public static GSSCredential createFromCertificateAndKey(String certFile, String keyFile, char[] certPassphrase, int lifetime_in_hours) {
		return PlainProxy.init(certFile, keyFile, certPassphrase,
				lifetime_in_hours);
	}

	public static GSSCredential createFromCertificateAndKeyCommandline(String certFile, String keyFile, int lifetime_in_hours) {

		if (StringUtils.isBlank(certFile)) {
			certFile = LocalProxy.CERT_FILE;
		}
		if (StringUtils.isBlank(keyFile)) {
			keyFile = LocalProxy.KEY_FILE;
		}

		if (lifetime_in_hours<=0) {
			lifetime_in_hours = 12;
		}

		char[] pw = CliLogin
				.askPassword("Please enter your certificate passphrase");

		return createFromCertificateAndKey(certFile, keyFile, pw,
				lifetime_in_hours);
	}

	public static GSSCredential createFromCommandline() {
		return createFromCommandline(null);
	}

	public static GSSCredential createFromCommandline(Set<LoginType> types) {
		if ((types == null) || (types.size() == 0)) {

			final String lastIdp = CommonGridProperties.getDefault()
					.getGridProperty(CommonGridProperties.Property.SHIB_IDP);


			if (StringUtils.isBlank(lastIdp)) {
				types = ImmutableSet.of(LoginType.SHIBBOLETH,
						LoginType.MYPROXY, LoginType.X509_CERTIFICATE);

			} else {
				types = ImmutableSet.of(LoginType.SHIBBOLETH,
						LoginType.SHIBBOLETH_LAST_IDP, LoginType.MYPROXY,
						LoginType.X509_CERTIFICATE);

			}
		}

		String msg = "Please select your preferred login method:";

		final ImmutableList<LoginType> temp = ImmutableList.copyOf(types);
		List<String> typeStrings = new LinkedList<String>();
		for (int i = 0; i < temp.size(); i++) {
			if (temp.get(i).equals(LoginType.SHIBBOLETH_LAST_IDP)) {
				final String lastIdp = CommonGridProperties.getDefault()
						.getLastShibIdp();
				typeStrings.add(temp.get(i).getPrettyName() + " (using: "
						+ lastIdp + ")");
			} else {
				typeStrings.add(temp.get(i).getPrettyName());
			}
		}

		String choice = CliLogin.ask("Login method", null, typeStrings, msg,
				true);

		int index = typeStrings.indexOf(choice);

		if (index == -1) {
			return null;
		}

		LoginType type = temp.get(index);
		GSSCredential cred = null;

		switch (type) {
		case X509_CERTIFICATE:
			cred = createFromCertificateAndKeyCommandline(null, null, -1);
			break;
		case SHIBBOLETH:
			cred = createFromShibIdpCommandline();
			break;
		case SHIBBOLETH_LAST_IDP:
			cred = createFromShibIdpCommandline(null, CommonGridProperties
					.getDefault().getLastShibUsername());
			break;
		default:
			throw new IllegalArgumentException("Login type " + type
					+ " not supported");
		}

		return cred;
	}

	private static GSSCredential createFromShibIdpCommandline() {

		List<String> idps = null;
		try {
			CliHelpers.setIndeterminateProgress(
					"Loading list of institutions...", true);
			idps = SlcsLoginWrapper.getAllIdps();
		} catch (Throwable e) {
			throw new CredentialException("Could not list idps: "
					+ e.getLocalizedMessage());
		} finally {
			CliHelpers.setIndeterminateProgress(false);
		}

		String lastIdp = CommonGridProperties.getDefault().getLastShibIdp();
		String idp = CliLogin.ask("Your institution", lastIdp, idps,
				"Please select the institution you are associated with:", true);

		return createFromShibIdpCommandline(idp, null);

	}

	private static GSSCredential createFromShibIdpCommandline(String idp, String username) {
		if ( StringUtils.isBlank(idp) ) {
			idp = CommonGridProperties.getDefault().getLastShibIdp();
			if (StringUtils.isBlank(idp)) {
				throw new RuntimeException("No idp provided.");
			}
		}

		if (StringUtils.isBlank(username)) {
			String msg = "Your institution username";
			String lastUsername = CommonGridProperties.getDefault()
					.getLastShibUsername();

			username = CliLogin.ask(msg, lastUsername);
		} else {
			System.out.println("Logging in to \"" + idp + "\", username: "
					+ username);
		}

		char[] pw = CliLogin.askPassword("Your institution password");

		CliHelpers.setIndeterminateProgress("Logging in...", true);
		try {
			GSSCredential gss = createFromSlcs(CredentialFactory.SLCS_URL, idp,
					username, pw);
			return gss;
		} finally {
			CliHelpers.setIndeterminateProgress(false);
		}
	}

	public static GSSCredential createFromSlcs(String url, String idp, String username, char[] password) {
		myLogger.debug("SLCS login: setting idpObject and credentialManager...");
		final IdpObject idpO = new StaticIdpObject(idp);
		final CredentialManager cm = new StaticCredentialManager(username,
				password);

		myLogger.debug("SLCS login: starting actual login...");

		if (StringUtils.isBlank(url)) {
			url = SLCS.DEFAULT_SLCS_URL;
		}

		final SLCS slcs = new SLCS(url, idpO, cm);
		if ((slcs.getCertificate() == null) || (slcs.getPrivateKey() == null)) {
			myLogger.debug("SLCS login: Could not get SLCS certificate and/or SLCS key...");
			throw new CredentialException(
					"Could not get SLCS certificate and/or SLCS key...");
		}

		myLogger.debug("SLCS login: Login finished.");
		myLogger.debug("SLCS login: Creating proxy from slcs credential...");

		final GSSCredential gss = PlainProxy.init(slcs.getCertificate(),
				slcs.getPrivateKey(), 24 * 10);
		return gss;
	}

	public static Properties getPropertiesFromFile(String localPath)
			throws CredentialException {
		try {
			Properties p = new Properties();
			p.load(new FileInputStream(localPath));
			return p;
		} catch (Exception e) {
			throw new CredentialException(e);
		}
	}
	public static void main(String[] args) throws Exception {

		// VomsesFiles.copyVomses();
		//
		Credential c = CredentialFactory.createFromCommandline();
		c.uploadMyProxy();
		c.saveCredential();
		//
		// System.out.println("\t"
		// + StringUtils.join(c.getAvailableFqans().keySet(), "\n\t"));
		// c.getVomsCredential("/nz/nesi", true);
		// c.getVomsCredential("/nz/test", true);
		// c.uploadMyProxy();

		// CredentialListener l = new CredentialListener() {
		//
		// public void credentialAboutToExpire(Credential cred) {
		//
		// System.out.println("Credential about to expire");
		//
		// }

		//
		// System.out.println("Waiting...");
		//
		// int expiry = c.getRemainingLifetime();
		// c.fireCredentialExpiryReminder(l, expiry - 5);
		//
		// c.saveCredential();
		long start = new Date().getTime();
		Credential c2 = new Credential("/tmp/x509up_u1000", false);
		c2.uploadMyProxy();
		// c2.saveCredential();
		long end = new Date().getTime();
		System.out.println("Enddate: " + c2.getEndDate().getTime().toString());

		System.out.println("Duration: " + (end - start));

		c2.destroy();
		//
		// Credential c3 = c2.getVomsCredential("/nz/nesi");
		// c3.uploadMyProxy();
		//
		// c2.saveCredential();


	}

	private GSSCredential cred = null;
	private String myProxyUsername = null;

	private char[] myProxyPassword = null;

	private boolean myproxyCredential = false;

	private boolean uploaded = false;
	private String myProxyHostOrig = DEFAULT_MYPROXY_SERVER;

	private int myProxyPortOrig = DEFAULT_MYPROXY_PORT;

	private String myProxyHostNew = null;

	private int myProxyPortNew = -1;
	private String localPath = null;

	private final String fqan;

	private final UUID uuid = UUID.randomUUID();

	private Map<String, VO> fqans;

	private Calendar endTime;

	private final List<ExpiryReminder> expiryReminders = Lists.newLinkedList();

	private Timer timer = new Timer("credentialExpiryTimer", true);

	private final Map<PROPERTY, Object> properties = Maps.newHashMap();

	private String certFile;

	private String keyFile;

	private final Map<String, Credential> children = Maps.newConcurrentMap();



	public Credential() {
		this(CredentialHelpers
				.loadGssCredential(new File(LocalProxy.PROXY_FILE)));
		this.localPath = LocalProxy.PROXY_FILE;
		properties.put(PROPERTY.LoginType, LoginType.LOCAL_PROXY);
	}

	/**
	 * Creates a Credential object from an x509 certificate and key pair that
	 * sits in the default globus location (usually $HOME/.globus/usercert.pem &
	 * userkey.pem) using the {@link #DEFAULT_PROXY_LIFETIME_IN_HOURS}.
	 * 
	 * @param passphrase
	 *            the certificate passphrase
	 * @throws CredentialException
	 *             if the proxy could not be created
	 */
	public Credential(char[] passphrase) throws CredentialException {
		this(CoGProperties.getDefault().getUserCertFile(), CoGProperties.getDefault().getUserKeyFile(), passphrase, DEFAULT_PROXY_LIFETIME_IN_HOURS);
	}

	/**
	 * Creates a Credential object from an x509 certificate and key pair that
	 * sits in the default globus location (usually $HOME/.globus/usercert.pem &
	 * userkey.pem).
	 * 
	 * @param passphrase
	 *            the certificate passphrase
	 * @param lifetime_in_hours
	 *            the lifetime of the proxy in hours
	 * @throws CredentialException
	 *             if the proxy could not be created
	 */
	public Credential(char[] passphrase, int lifetime_in_hours)
			throws CredentialException {
		this(CoGProperties.getDefault().getUserCertFile(), CoGProperties
				.getDefault().getUserKeyFile(), passphrase, lifetime_in_hours);
	}

	/**
	 * Creates a Credential object using the provided GSSCredential as base
	 * credential.
	 * 
	 * @param cred
	 *            a GSSCredential
	 * 
	 * @throws CredentialException
	 *             if the provided credential is not valid
	 */
	public Credential(GSSCredential cred) throws CredentialException {

		this.myproxyCredential = false;
		this.fqan = null;

		initGSSCredential(cred);

		properties.put(PROPERTY.LoginType, LoginType.UNDEFINED);

	}

	public Credential(GSSCredential cred, String fqan) {

		this(cred, VOManagement.getAllFqans(cred).get(fqan), fqan);

	}


	/**
	 * Creates a new, VOMS-enabled credential out of the provided base
	 * credential.
	 * 
	 * @param cred
	 *            the base credential, this would usually have no voms attribute
	 *            certificate attached
	 * @param vo
	 *            the VO the new credential gets its attribute credential from
	 * @param fqan
	 *            the fqan (group) of the new credential
	 * @throws CredentialException
	 *             if the provided credential is not valid or the voms attribute
	 *             certificate could not be created
	 */
	public Credential(GSSCredential cred, VO vo, String fqan)
			throws CredentialException {

		this.fqan = fqan;
		try {
			VomsProxy vp = new VomsProxy(vo, fqan,
					CredentialHelpers.unwrapGlobusCredential(cred), new Long(
							cred.getRemainingLifetime()) * 1000);

			this.cred = CredentialHelpers.wrapGlobusCredential(vp
					.getVomsProxyCredential());
			this.myproxyCredential = false;
		} catch (Exception e) {
			throw new CredentialException("Can't create voms credential.", e);
		}

		getCredential();

		properties.put(PROPERTY.LoginType, LoginType.UNDEFINED);
	}

	public Credential(Properties p, String group, boolean check) {

		initProperties(p, group, check);

		fqan = group;
		LoginType lt = (LoginType) properties.get(PROPERTY.LoginType);
		if (LoginType.MYPROXY.equals(lt)) {
			this.myproxyCredential = true;
		} else {
			this.myproxyCredential = false;
		}


	}

	/**
	 * Creates a Credential object out of an existing metadataFile or proxy.
	 * 
	 * First, the metadata file is tried, if it exists, the credential is build
	 * out of information in it. If not, a local proxy cert is used (if it
	 * exists).
	 * 
	 * @param localPath
	 *            the path to the proxy credential
	 * @throws CredentialException
	 *             if the credential at the specified path is not valid
	 */
	public Credential(String localPath)
			throws CredentialException {

		this(localPath, true);
	}

	/**
	 * Creates a Credential object out of an existing metadataFile.
	 * 
	 * This proxy would usually be on the default globus location (e.g.
	 * /tmp/<x509u...>.mp for Linux).
	 * 
	 * @param localPath
	 *            the path to the metadata credential
	 * @param check
	 *            whether to check on the MyProxy server if the proxy actually
	 *            exists
	 * @throws CredentialException
	 *             if the credential at the specified path is not valid
	 */
	public Credential(String localPath, boolean check) {

		File proxyMD = new File(localPath+"."+METADATA_FILE_EXTENSION);
		fqan = null;
		this.localPath = localPath;


		if ( proxyMD.exists() ) {

			Properties props = getPropertiesFromFile(proxyMD.getAbsolutePath());
			String md5 = (String) props.get(PROPERTY.md5sum.toString());
			File proxy = new File(localPath);
			String md5File = null;
			try {
				String proxyString = FileUtils.readFileToString(proxy);
				md5File = DigestUtils.md5Hex(proxyString);
			} catch (Exception e) {
			}

			if (StringUtils.isNotBlank(md5) && proxy.exists()
					&& !md5.equals(md5File)) {

				// delete metadata file and load from proxy
				FileUtils.deleteQuietly(proxyMD);

				this.myproxyCredential = false;

				initGSSCredential(CredentialHelpers.loadGssCredential(new File(
						localPath)));

				properties.put(PROPERTY.LoginType, LoginType.LOCAL_PROXY);

			} else {
				// load from properties
				initProperties(
						getPropertiesFromFile(proxyMD.getAbsolutePath()),
						null, check);
				LoginType lt = LoginType.valueOf((String) properties
						.get(PROPERTY.LoginType));
				if (LoginType.MYPROXY.equals(lt)) {
					this.myproxyCredential = true;
				} else {
					this.myproxyCredential = false;
				}
			}

		} else {
			// load from proxy
			File proxy = new File(localPath);
			if (!proxy.exists()) {
				throw new CredentialException("No proxy found on: " + localPath);
			}
			this.myproxyCredential = false;

			initGSSCredential(CredentialHelpers.loadGssCredential(new File(
					localPath)));

			properties.put(PROPERTY.LoginType, LoginType.LOCAL_PROXY);
		}


	}

	/**
	 * Creates a Credential object from MyProxy login information.
	 * 
	 * @param myProxyUsername
	 *            the MyProxy username
	 * @param myProxyPassword
	 *            the MyProxy password
	 * @param myproxyHost
	 *            the MyProxy host
	 * @param myproxyPort
	 *            the MyProxy port
	 * @throws CredentialException
	 *             if no valid proxy could be retrieved from MyProxy
	 */
	public Credential(String myProxyUsername, char[] myProxyPassword,
			String myproxyHost, int myproxyPort)
					throws CredentialException {

		this.myProxyUsername = myProxyUsername;
		this.myProxyPassword = myProxyPassword;
		this.myproxyCredential = true;
		if (StringUtils.isBlank(myproxyHost)) {
			this.myProxyHostOrig = GridEnvironment.getDefaultMyProxyServer();
		} else {
			this.myProxyHostOrig = myproxyHost;
		}
		if (myproxyPort <= 0) {
			this.myProxyPortOrig = GridEnvironment.getDefaultMyProxyPort();
		} else {
			this.myProxyPortOrig = myproxyPort;
		}

		getCredential();
		// TODO: check cred for vo info
		this.fqan = Constants.NON_VO_FQAN;

		properties.put(PROPERTY.LoginType, LoginType.MYPROXY);
		properties.put(PROPERTY.MyProxyUsername, myProxyUsername);
		properties.put(PROPERTY.MyProxyPassword, new String(myProxyPassword));
		properties.put(PROPERTY.MyProxyHost, myproxyHost);
		properties.put(PROPERTY.MyProxyPort, myproxyPort);

	}

	/**
	 * This one creates a Credential object by creating a proxy out of a local
	 * X509 certificate & key.
	 * 
	 * @param certFile
	 *            the path to the certificate
	 * @param keyFile
	 *            the path to the key
	 * @param certPassphrase
	 *            the passphrase for the certificate
	 * @param lifetime_in_hours
	 *            the lifetime of the proxy
	 * @throws IOException
	 * @throws GSSException
	 * @throws Exception
	 */
	public Credential(String certFile, String keyFile, char[] certPassphrase,
			int lifetime_in_hours) throws CredentialException {

		this.certFile = certFile;
		this.keyFile = keyFile;
		this.cred = createFromCertificateAndKey(certFile, keyFile,
				certPassphrase, lifetime_in_hours);

		this.myproxyCredential = false;
		this.myProxyHostOrig = DEFAULT_MYPROXY_SERVER;
		this.myProxyPortOrig = DEFAULT_MYPROXY_PORT;

		this.myProxyHostNew = this.myProxyHostOrig;
		this.myProxyPortNew = this.myProxyPortOrig;

		this.fqan = Constants.NON_VO_FQAN;

		getCredential();
		properties.put(PROPERTY.LoginType, LoginType.X509_CERTIFICATE);
	}

	/**
	 * Destroys proxy and possibly metadata file
	 */
	public void destroy() {
		if (StringUtils.isNotBlank(localPath)) {
			if (new File(localPath).exists()) {
				myLogger.debug("Deleting proxy file " + localPath);
				Util.destroy(localPath);
			}
			if (new File(localPath + "." + METADATA_FILE_EXTENSION).exists()) {
				myLogger.debug("Deleting proxy metadata file " + localPath
						+ "." + METADATA_FILE_EXTENSION);
				Util.destroy(localPath + "." + METADATA_FILE_EXTENSION);
			}
		}

		if (LoginType.MYPROXY.equals(properties.get(PROPERTY.LoginType))) {
			myLogger.debug("Destrying original proxy from host: "
					+ myProxyHostOrig);
			try {
				MyProxy mp = new MyProxy(myProxyHostOrig, myProxyPortOrig);
				mp.destroy(getCredential(), myProxyUsername, new String(
						myProxyPassword));
			} catch (MyProxyException e) {
				myLogger.error("Can't destroy myproxy credential.", e);
			}
		}

		if (uploaded
				&& (!myProxyHostNew.equals(myProxyHostOrig) || !LoginType.MYPROXY
						.equals(properties.get(PROPERTY.LoginType)))) {

			myLogger.debug("Destrying uploaded proxy from host: "
					+ myProxyHostNew);
			MyProxy mp = new MyProxy(myProxyHostNew, myProxyPortNew);
			try {
				mp.destroy(getCredential(), myProxyUsername, new String(
						myProxyPassword));
			} catch (MyProxyException e) {
				myLogger.error("Can't destroy myproxy credential.", e);
			}
		}

	}

	@Override
	public boolean equals(Object o) {
		if (o instanceof Credential) {
			Credential other = (Credential)o;
			if ( myproxyCredential ) {
				if ( myProxyUsername.equals(other.getMyProxyUsername())
						&& Arrays.equals(myProxyPassword, other.getMyProxyPassword()) ) {
					return true;
				} else {
					return false;
				}
			} else {
				try {
					return getCredential().equals(((Credential) o).getCredential());
				} catch (CredentialException e) {
					return false;
				}
			}
		} else {
			return false;
		}

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
	public void fireCredentialExpiryReminder(final CredentialListener l,
			final int secondsBeforeExpiry) {

		int remainingLifetime = getRemainingLifetime();
		int wait = remainingLifetime - secondsBeforeExpiry;
		if (wait <= 0) {
			wait = 1;
		}

		ExpiryReminder er = new ExpiryReminder(l, secondsBeforeExpiry);
		expiryReminders.add(er);
		timer.schedule(er.getTask(), wait * 1000);

	}


	/**
	 * Get a map of all Fqans (and VOs) the user has access to.
	 * 
	 * @return the Fqans of the user
	 */
	public synchronized Map<String, VO> getAvailableFqans() {

		if ( fqans == null ) {
			fqans = VOManagement.getAllFqans(getCredential());
		}
		return fqans;

	}

	/**
	 * The underlying GSSCredential.
	 * 
	 * @return the credential
	 * @throws CredentialException
	 *             if the credential can't be retrieved from MyProxy or the
	 *             lifetime of the credential is shorter than configured in
	 *             {@link #MIN_REMAINING_LIFETIME}.
	 */
	public GSSCredential getCredential() throws CredentialException {

		if ( this.cred == null ) {
			// means, get it from myproxy
			try {
				cred = MyProxy_light.getDelegation(myProxyHostOrig, myProxyPortOrig,
						myProxyUsername, myProxyPassword,
						DEFAULT_PROXY_LIFETIME_IN_HOURS * 3600);
			} catch (MyProxyException e) {
				throw new CredentialException(
						"Can't retrieve credential from MyProxy", e);
			}

		}
		try {
			if (this.cred.getRemainingLifetime() < MIN_REMAINING_LIFETIME) {
				if (!myproxyCredential) {
					throw new CredentialException(
							"Min lifetime shorter than threshold.");
				}
			}
		} catch (GSSException e) {
			throw new CredentialException("Can't get remaining lifetime from credential", e);
		}

		return cred;
	}

	public Calendar getEndDate() {
		if ( this.endTime == null ) {
			endTime = Calendar.getInstance();
			endTime.add(Calendar.SECOND, getRemainingLifetime());
			properties.put(PROPERTY.EndDate, endTime.getTimeInMillis());
		}
		return endTime;
	}

	/**
	 * If this credential is voms-enabled this method returns the fqan that is
	 * used for it.
	 * 
	 * @return the fqan or {@link Constants#NON_VO_FQAN}
	 */
	public String getFqan() {

		return this.fqan;
	}

	public String getLocalPath() {

		return localPath;
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

		if (myproxyCredential) {
			return myProxyPassword;
		} else {
			if (myProxyPassword != null) {
				return myProxyPassword;
			} else {
				myProxyPassword = new RandPass().getPassChars(10);
				return myProxyPassword;
			}
		}
	}

	public int getMyProxyPort() {
		return this.myProxyPortNew;
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
		return myProxyHostNew;
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
				// try {
				// myProxyUsername = cred.getName().toString()
				// + UUID.randomUUID().toString();
				// } catch (Exception e) {
				myProxyUsername = UUID.randomUUID().toString();
				// }
				return myProxyUsername;
			}

		}
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
			throw new CredentialException("Can't get remaining lifetime from credential.", e);
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
	public Credential getVomsCredential(String fqan)
			throws CredentialException {
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
		if ( vo == null ) {
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
		if ( c != null ) {
			return c;
		}

		Credential child = new Credential(getCredential(), vo, fqan);
		children.put(fqan, child);
		if (upload) {
			child.uploadMyProxy(myProxyHostNew, myProxyPortNew);
		}
		return child;
	}

	@Override
	public int hashCode() {
		if ( myproxyCredential ) {
			return (myProxyPassword.hashCode() + myProxyPassword.hashCode()) * 32;
		} else {
			try {
				return getCredential().hashCode() * 432;
			} catch (CredentialException e) {
				return uuid.hashCode();
			}
		}
	}

	private void init() {

	}

	private void initGSSCredential(GSSCredential cred) {

		this.cred = cred;

		getCredential();

	}

	private void initProperties(Properties p, String group, boolean check) {
		Map<String, Properties> childs = Maps.newHashMap();

		for (Enumeration<?> keys = p.propertyNames(); keys
				.hasMoreElements();) {
			String key = (String) keys.nextElement();
			try {
				PROPERTY prop = PROPERTY.valueOf(key);
				properties.put(prop, p.get(key));
			} catch (IllegalArgumentException iae) {

				// means it is not a property, probably child
				if (!key.startsWith(CHILD_KEY)) {
					myLogger.debug("Ignoring property "+key+"...");
					continue;
				}

				String[] tokens = key.split("\\.");

				String fqan = tokens[1];
				String property = tokens[2];
				String value = p.getProperty(key);
				Properties ptemp = childs.get(fqan);
				if (ptemp == null) {
					ptemp = new Properties();
					childs.put(fqan, ptemp);
				}
				ptemp.put(property, value);

			}
		}

		boolean origMyProxy = LoginType.MYPROXY.equals(properties
				.get(PROPERTY.LoginType));

		for (PROPERTY pr : properties.keySet()) {
			switch (pr) {
			case MyProxyUsername:
				myProxyUsername = (String) properties.get(pr);
				break;
			case MyProxyPassword:
				myProxyPassword = ((String) properties.get(pr)).toCharArray();
				uploaded = true;
				break;
			case MyProxyHost:
				if (origMyProxy) {
					myProxyHostOrig = (String) properties.get(pr);
				}
				myProxyHostNew = (String) properties.get(pr);
				break;
			case MyProxyPort:
				if (origMyProxy) {
					myProxyPortOrig = Integer.parseInt((String) properties
							.get(pr));
				}
				myProxyPortNew = Integer.parseInt((String) properties.get(pr));
				break;
			}
		}

		if (check) {
			try {
				getCredential().getRemainingLifetime();
			} catch (Exception e) {
				throw new CredentialException(
						"Can't retrieve credential from MyProxy.", e);
			}
		}



		for (String fqan : childs.keySet()) {
			Credential c = new Credential(childs.get(fqan), fqan, check);
			children.put(fqan, c);
		}

		for (PROPERTY pr : properties.keySet()) {
			System.out.println("PROPERTY: " + pr + ": " + properties.get(pr));
		}

		for (String fqan : childs.keySet()) {
			System.out.println("Child " + fqan);
			Properties ptemp = childs.get(fqan);
			for (Object key : ptemp.keySet()) {
				System.out.println("\t" + key.toString() + " - "
						+ ptemp.getProperty((String) key).toString());
			}
		}
	}

	/**
	 * Destroys this Credential on the MyProxy server.
	 * 
	 * this doesn't delete a possibly existing local proxy.
	 * 
	 * @throws CredentialException
	 *             if the credential could not be destroyed
	 */
	public void invalidate() throws CredentialException {

		myLogger.debug("Invalidating credential for " + fqan);

		DestroyParams request = new DestroyParams();
		request.setUserName(myProxyUsername);
		request.setPassphrase(new String(myProxyPassword));

		MyProxy mp = new MyProxy(myProxyHostNew, myProxyPortNew);
		try {
			mp.destroy(getCredential(), request);
		} catch (Exception e) {
			throw new CredentialException(
					"Could not destroy myproxy credential.", e);
		}

	}

	/**
	 * Whether this Credential was created from a MyProxy username/password
	 * combination.
	 * 
	 * @return whether this was created from MyProxy
	 */
	public boolean isMyProxyCredential() {
		return myproxyCredential;
	}

	public boolean isUploaded() {
		return this.uploaded;
	}

	private void loadFromMetadataFile(String metadataFile) {

	}

	public synchronized void refreshCredential(GSSCredential cred) {
		this.timer.cancel();
		this.cred = cred;
		this.endTime = null;
		this.timer = new Timer("credentialExpiryTimer", true);
		for (ExpiryReminder er : expiryReminders) {

			int remainingLifetime = getRemainingLifetime();
			int wait = remainingLifetime - er.getSecondsBeforeExpiry();
			if (wait <= 0) {
				wait = 1;
			}
			this.timer.schedule(er.getTask(), wait * 1000);
		}

		if (StringUtils.isNotBlank(this.localPath)) {
			saveCredential();
		}
	}

	public synchronized boolean refreshCredentialCommandline() {

		Object ltO = getProperty(PROPERTY.LoginType);
		LoginType lt = null;
		if (ltO == null) {
			lt = LoginType.UNDEFINED;
		} else {
			lt = (LoginType) ltO;
		}
		GSSCredential newCred = null;
		switch (lt) {
		case X509_CERTIFICATE:
			newCred = createFromCertificateAndKeyCommandline(this.certFile,
					this.keyFile, DEFAULT_PROXY_LIFETIME_IN_HOURS);
			break;
		case SHIBBOLETH:
			newCred = createFromShibIdpCommandline(CommonGridProperties
					.getDefault().getLastShibIdp(), CommonGridProperties
					.getDefault().getLastShibUsername());
			break;
		case SHIBBOLETH_LAST_IDP:
			newCred = createFromShibIdpCommandline(CommonGridProperties
					.getDefault().getLastShibIdp(), CommonGridProperties
					.getDefault().getLastShibUsername());
			break;
		case MYPROXY:
			this.cred = null;
			getCredential();
			return true;
		default:
			newCred = createFromCommandline();
			break;
		}

		if (newCred == null) {
			return false;
		} else {
			refreshCredential(newCred);
			return true;
		}

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

		getEndDate();

		Properties prop = new Properties();

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

		// TODO: check whether new upload is required?
		if (uploaded == true) {
			return;
		}

		if (StringUtils.isNotBlank(myProxyHostUp)) {
			this.myProxyHostNew = myProxyHostUp;
		} else {
			this.myProxyHostNew = myProxyHostOrig;
		}

		if (myProxyPortUp > 0) {
			this.myProxyPortNew = myProxyPortUp;
		} else {
			this.myProxyPortNew = myProxyPortOrig;
		}

		if (myproxyCredential
				&& (this.myProxyHostOrig.equals(this.myProxyHostNew) && (this.myProxyPortOrig == this.myProxyPortNew))) {
			// doesn't make sense in that case
			return;
		}

		myLogger.debug("Uploading credential to: " + myProxyHostNew);

		MyProxy mp = MyProxy_light.getMyProxy(myProxyHostNew, myProxyPortNew);


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
			properties.put(PROPERTY.MyProxyUsername, getMyProxyUsername());
			properties.put(PROPERTY.MyProxyPassword, new String(
					getMyProxyPassword()));
			properties.put(PROPERTY.MyProxyHost, myProxyHostNew);
			properties.put(PROPERTY.MyProxyPort, new Integer(myProxyPortNew));
		} catch (Exception e) {
			throw new CredentialException("Can't upload MyProxy", e);
		}

	}


}
