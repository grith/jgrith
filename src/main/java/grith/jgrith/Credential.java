package grith.jgrith;

import grisu.jcommons.constants.Constants;
import grisu.jcommons.constants.GridEnvironment;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.myProxy.MyProxy_light;
import grith.jgrith.plainProxy.LocalProxy;
import grith.jgrith.plainProxy.PlainProxy;
import grith.jgrith.voms.VO;
import grith.jgrith.voms.VOManagement.VOManagement;
import grith.jgrith.vomsProxy.VomsProxy;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.globus.common.CoGProperties;
import org.globus.myproxy.DestroyParams;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.Ostermiller.util.RandPass;

/**
 * A wrapper class that wraps a {@link GSSCredential} and provides convenience
 * constructors and methods, like MyProxy- and VOMS-access and state management.
 * 
 * @author Markus Binsteiner
 * 
 */
public class Credential {

	static final Logger myLogger = LoggerFactory.getLogger(Credential.class
			.getName());

	public final static String DEFAULT_MYPROXY_SERVER = GridEnvironment
			.getDefaultMyProxyServer();
	public final static int DEFAULT_MYPROXY_PORT = GridEnvironment
			.getDefaultMyProxyPort();

	public final static int DEFAULT_PROXY_LIFETIME_IN_HOURS = 12;

	public final static int MIN_REMAINING_LIFETIME = 600;

	private GSSCredential cred = null;
	private String myProxyUsername = null;
	private char[] myProxyPassword = null;

	private boolean myproxyCredential = false;
	private boolean uploaded = false;

	private final String myProxyHostOrig;
	private final int myProxyPortOrig;

	private String myProxyHostNew = null;
	private int myProxyPortNew = -1;

	private String localPath = null;

	private final String fqan;

	private final UUID uuid = UUID.randomUUID();

	private Map<String, VO> fqans;

	public Credential() {

		this(LocalProxy.PROXY_FILE);

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
		this(CoGProperties.getDefault().getUserCertFile(), CoGProperties.getDefault().getUserKeyFile(), passphrase, lifetime_in_hours);
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
		this.cred = cred;
		this.myproxyCredential = false;
		this.fqan = Constants.NON_VO_FQAN;

		this.myProxyHostOrig = DEFAULT_MYPROXY_SERVER;
		this.myProxyPortOrig = DEFAULT_MYPROXY_PORT;

		this.myProxyHostNew = this.myProxyHostOrig;
		this.myProxyPortNew = this.myProxyPortOrig;

		getCredential();
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

		this.myProxyHostOrig = DEFAULT_MYPROXY_SERVER;
		this.myProxyPortOrig = DEFAULT_MYPROXY_PORT;

		this.myProxyHostNew = this.myProxyHostOrig;
		this.myProxyPortNew = this.myProxyPortOrig;

	}

	/**
	 * Creates a Credential object out of an existing proxy credential.
	 * 
	 * This proxy would usually be on the default globus location (e.g.
	 * /tmp/x509u.... for Linux).
	 * 
	 * @param localPath
	 *            the path to the proxy credential
	 * @throws CredentialException
	 *             if the credential at the specified path is not valid
	 */
	public Credential(String localPath) throws CredentialException {

		this(CredentialHelpers.loadGssCredential(new File(localPath)));

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

		this.myProxyHostNew = this.myProxyHostOrig;
		this.myProxyPortNew = this.myProxyPortOrig;

		getCredential();
		// TODO: check cred for vo info
		this.fqan = Constants.NON_VO_FQAN;
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

		this.cred = PlainProxy.init(certFile, keyFile, certPassphrase,
				lifetime_in_hours);

		this.myproxyCredential = false;
		this.myProxyHostOrig = DEFAULT_MYPROXY_SERVER;
		this.myProxyPortOrig = DEFAULT_MYPROXY_PORT;

		this.myProxyHostNew = this.myProxyHostOrig;
		this.myProxyPortNew = this.myProxyPortOrig;

		this.fqan = Constants.NON_VO_FQAN;

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
	public Credential createVomsCredential(String fqan)
			throws CredentialException {

		VO vo = getAvailableFqans().get(fqan);
		if ( vo == null ) {
			throw new CredentialException("Can't find VO for fqan: " + fqan);
		} else {
			return createVomsCredential(vo, fqan);
		}

	}

	/**
	 * Creates a new, voms-enabled Credential object from an arbitrary VO.
	 * 
	 * @param vo
	 *            the VO
	 * @param fqan
	 *            the fqan
	 * @return the Credential
	 * @throws CredentialException
	 *             if the Credential can't be created (e.g. voms error).
	 */
	public Credential createVomsCredential(VO vo, String fqan)
			throws CredentialException {
		return new Credential(getCredential(), vo, fqan);
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

		} else {
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
		}
		return cred;
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

		if ( localPath == null ) {
			try {
				CredentialHelpers.writeToDisk(getCredential(), new File(
						LocalProxy.PROXY_FILE));
				localPath = LocalProxy.PROXY_FILE;
			} catch (Exception e) {
				myLogger.error(
						"Could  not write credential: "
								+ e.getLocalizedMessage(), e);
				throw new RuntimeException(e);
			}
		}
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
	}

	public void setMyProxyDelegatedPassword(char[] myProxyPassphrase) {
		this.myProxyPassword = myProxyPassphrase;
	}

	public void setMyProxyDelegatedUsername(String myProxyUsername2) {
		this.myProxyUsername = myProxyUsername2;
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
		}

		if (myProxyPortUp > 0) {
			this.myProxyPortNew = myProxyPortUp;
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
					null, null, null, null,
					DEFAULT_PROXY_LIFETIME_IN_HOURS * 3600);
		} catch (MyProxyException e) {
			throw new CredentialException("Can't prepare myproxy parameters", e);
		}

		try {
			MyProxy_light.init(mp, getCredential(), params,
					getMyProxyPassword());
			uploaded = true;
		} catch (Exception e) {
			throw new CredentialException("Can't upload MyProxy", e);
		}

	}

}
