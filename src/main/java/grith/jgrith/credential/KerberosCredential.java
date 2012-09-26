package grith.jgrith.credential;

import grith.jgrith.cred.AbstractCred;
import grith.jgrith.cred.Cred;
import grith.jgrith.credential.Credential.PROPERTY;
import grith.jgrith.kerberos.SimpleMyProxyClient;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ietf.jgss.GSSCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KerberosCredential extends AbstractCred implements Cred {

	public static final String DEFAULT_SERVICE_NAME = "myproxy";
	public static final String DEFAULT_REALM = "NESI.ORG.NZ";
	public static final String DEFAULT_HOST = "myproxyca.nesi.org.nz";
	
	public static final int DEFAULT_KERBEROS_LIFETIME = 8 * 3600;
	public static final int MYPROXY_PORT = 7512;
	public static final String JAAS_SERVICE_NAME = "JaasGrisu";

	static final Logger myLogger = LoggerFactory
			.getLogger(KerberosCredential.class.getName());

	private String principalName;
	private String myproxyServiceName;
	private String myproxycaDN;
	private String myproxycaRealm;
	private String password;
	
	static {
		String jaasConf = KerberosCredential.class.getResource("/jaas.conf").toExternalForm();
		System.setProperty("java.security.auth.login.config", jaasConf);
		System.setProperty("java.security.krb5.conf","/home/yhal003/projects/jgrith/target/classes/krb5.conf");
		System.setProperty("sun.security.krb5.debug", "true");
	}

	public KerberosCredential(String principalName, String proxyServiceName,
			String myproxycaDN, String myproxycaRealm, String password) {
		this.principalName = principalName;
		this.myproxyServiceName = proxyServiceName;
		this.myproxycaDN = myproxycaDN;
		this.myproxycaRealm = myproxycaRealm;
		this.password = password;
	}

	public KerberosCredential(String principalName, String myproxycaDN,
			String myproxycaRealm, String password) {
		this(principalName, DEFAULT_SERVICE_NAME, myproxycaDN, myproxycaRealm,
				password);
	}
	
	public KerberosCredential(String principalName, String password){
		this(principalName, DEFAULT_SERVICE_NAME, DEFAULT_HOST, DEFAULT_REALM, password);
	}

	public static void main(String[] args) {
		System.out.println("test");
		Security.addProvider(new BouncyCastleProvider());
		KerberosCredential kc = new KerberosCredential(
				"yhal003@NESI.ORG.NZ", "boaduisu");
		GSSCredential cred = kc.createGSSCredentialInstance();
	}

	@Override
	public GSSCredential createGSSCredentialInstance() {

		try {
			LoginContext lc = new LoginContext(JAAS_SERVICE_NAME,
					new SimpleCallbackHandler());
			lc.login();
			System.out.println(lc.getSubject());
			GSSCredential result = Subject.doAs(lc.getSubject(),
					new GetCertificateAction());
			
			return result;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void initCred(Map<PROPERTY, Object> config) {

	}

	@Override
	public boolean isRenewable() {
		// not sure how to do that yet.
		return false;
	}

	class SimpleCallbackHandler implements CallbackHandler {

		@Override
		public void handle(Callback[] cs) throws IOException,
				UnsupportedCallbackException {
			for (Callback c : cs) {
				if (c instanceof NameCallback) {
					((NameCallback) c).setName(principalName);
				} else if (c instanceof PasswordCallback) {
					((PasswordCallback) c).setPassword(password.toCharArray());
				}
			}

		}

	}

	class GetCertificateAction implements
			PrivilegedExceptionAction<GSSCredential> {

		@Override
		public GSSCredential run() throws PrivilegedActionException {

			try {

				SaslClient client = getSaslClient();
				
				SimpleMyProxyClient myproxy = SimpleMyProxyClient.create(
						myproxycaDN, MYPROXY_PORT);

				myproxy.connect();
				// myproxy.sendGetCommand(principalName, 1000000);
				myproxy.sendGetCommand(getUsername(), 10000);
				myproxy.doSasl(client);
				GSSCredential gssCred = myproxy.getCredential();
				
				return gssCred;

				// TODO Auto-generated method stub
			} catch (Exception sax) {
				sax.printStackTrace();
				myLogger.error("cannot create kerberos credential", sax);
				throw new PrivilegedActionException(sax);
			}
		}

	}
	
	private String getUsername() {
		if (principalName.contains(myproxycaRealm)){
			 return principalName.replace("@" + myproxycaRealm, "");
		}
		return principalName;
	}
	
	private SaslClient getSaslClient() throws SaslException {
		
		final Map<String, String> map = new HashMap<String, String>();
		map.put(Sasl.QOP, "auth");
		final SaslClient client = Sasl.createSaslClient(
				new String[] { "GSSAPI" }, getUsername(), myproxyServiceName,
				myproxycaDN, map, null);
		return client;
	}

}
