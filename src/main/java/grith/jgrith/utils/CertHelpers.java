package grith.jgrith.utils;

import grith.jgrith.certificate.ProxyCredentialOld;
import grith.jgrith.voms.VO;
import grith.jgrith.vomsProxy.VomsException;
import grith.jgrith.vomsProxy.VomsProxyCredential;

import org.globus.gsi.GlobusCredential;
import org.globus.gsi.ptls.PureTLSUtil;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper class that does stuff with certificates.
 * 
 * @author Markus Binsteiner
 * 
 */
public final class CertHelpers {

	static final Logger myLogger = LoggerFactory.getLogger(CertHelpers.class
			.getName());

	// static final Logger myLogger = LoggerFactory
	// .getLogger(CertHelpers.class.getName());

	/**
	 * Converts the dn from the /C=AU/O=... to the C=AU,O=.. format
	 * 
	 * @param cred
	 *            the credential as {@link GSSCredential}
	 * @return the dn of this certificate in the proper format
	 */
	public static String getDnInProperFormat(final GSSCredential cred) {
		String dn = null;
		try {
			dn = PureTLSUtil.getX509Name(cred.getName().toString())
					.getNameString();
		} catch (final GSSException e) {
			myLogger.error(e.getLocalizedMessage(), e);
		} catch (final Exception e) {
			myLogger.error(e.getLocalizedMessage(), e);
		}
		return dn;
	}

	/**
	 * Converts the dn from the /C=AU/O=... to the C=AU,O=.. format
	 * 
	 * @param cred
	 *            the credential as {@link GlobusCredential}
	 * @return the dn of this certificate in the proper format
	 */
	public static String getDnInProperFromat(final GlobusCredential cred) {
		String dn = null;

		try {
			dn = PureTLSUtil.getX509Name(cred.getSubject()).getNameString();
		} catch (final Exception e) {
			myLogger.error(e.getLocalizedMessage(), e);
		}

		return dn;

	}

	/**
	 * This one uses the proxy_light library to create a voms proxy using a
	 * plain proxy.
	 * 
	 * @param vo
	 *            the vo to connect to to get the voms proxy
	 * @param fqan
	 *            the fqan which the newly created proxy should have
	 * @param credToConnect
	 *            the plain proxy
	 * @return the voms proxy
	 * @throws VomsException
	 *             if the communication with the voms server fails for some
	 *             reason
	 */
	public static ProxyCredentialOld getVOProxyCredential(final VO vo,
			final String fqan, final ProxyCredentialOld credToConnect) {
		//
		VomsProxyCredential vomsGssCred = null;
		try {
			final String group = FqanHelpers.getGroupPart(fqan);
			final String role = FqanHelpers.getRolePart(fqan);
			if ((role == null) || "NULL".equals(role)) {
				vomsGssCred = new VomsProxyCredential(
						CredentialHelpers.unwrapGlobusCredential(credToConnect
								.getGssCredential()), vo, "G" + group, null);
			} else {
				vomsGssCred = new VomsProxyCredential(
						CredentialHelpers.unwrapGlobusCredential(credToConnect
								.getGssCredential()), vo, "B" + group + ":"
										+ role, null);
			}
			// myLogger.debug("Created voms proxy for fqan: " + fqan
			// + " with lifetime: "
			// + vomsGssCred.getVomsProxy().getTimeLeft());

		} catch (final Exception e) {
			throw new RuntimeException(
					"Could not retrieve VomsProxyCredential for fqan \"" + fqan
					+ "\": " + e.getMessage());
		}

		ProxyCredentialOld vomsProxyCred = null;
		try {
			vomsProxyCred = new ProxyCredentialOld(
					CredentialHelpers.wrapGlobusCredential(vomsGssCred
							.getVomsProxy()), fqan);
		} catch (final Exception e) {
			throw new RuntimeException(
					"Could not retrieve VomsProxyCredential for fqan \"" + fqan
					+ "\": " + e.getMessage());
		}

		return vomsProxyCred;
	}

	private CertHelpers() {
	}

}
