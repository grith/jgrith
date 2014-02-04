package grith.jgrith.kerberos;

import javax.net.ssl.SSLSession;

import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author yhal003
 * This monstrosity is just to create ssl sockets that do not verify certificates. 
 * Will have to change it.
 */
public class MyProxySSLFactoryUtil {

	private static SSLSocketFactory factory;
	
	public static SSLSocketFactory getFactory(){
		return factory;
	}

	static final Logger myLogger = LoggerFactory
			.getLogger(MyProxySSLFactoryUtil.class.getName());

	static {
		try {
			final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				@Override
				public void checkClientTrusted(X509Certificate[] certs,
						String authType) {
				}

				@Override
				public void checkServerTrusted(X509Certificate[] chain,
						String authType) {
				}

				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return null;

				}
			} };

			SSLContext sc = SSLContext.getInstance("TLS");
			HostnameVerifier hv = new HostnameVerifier() {
				@Override
				public boolean verify(String arg0, SSLSession arg1) {
					return true;
				}

			};

			sc.init(new KeyManager[0], trustAllCerts,
					new java.security.SecureRandom());
			factory = sc.getSocketFactory();
		} catch (Exception e) {

		}
	}
	
	public static KeyPair generateKeyPair() {
		
		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator
					.getInstance("RSA", "BC");
		} catch (Exception e) {
			myLogger.error("cannot generate key pair",e);
			return null;
		} 
		keyPairGenerator.initialize(2048, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}
	
	public static PKCS10CertificationRequest generateRequest(KeyPair keyPair){
		
		X500Principal subjectName = new X500Principal(
				"CN=myproxyca doesn't care about it anyway");

		try {
			PKCS10CertificationRequest kpGen = new PKCS10CertificationRequest(
					"SHA512withRSA", subjectName, keyPair.getPublic(),
					null, keyPair.getPrivate());
			return kpGen;
		} catch (Exception e) {
			myLogger.error("cannot generate certificate request", e);
			return null;
		} 
	}
	
	
}
