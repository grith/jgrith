/* This class is a rewrite of the classes VOMSClient and
 * MyGloubsCredentialUtils
 *
 * Gidon Moont from
 * Imperial College London
 *
 * wrote. I did not change the functionality, just some things like
 * logging to use it better with grix.
 * So: all the credit goes to Gidon.
 */

package grith.jgrith.vomsProxy;

import gridpp.portal.voms.VOMSAttributeCertificate;
import gridpp.portal.voms.VincenzoBase64;
import grisu.jcommons.exceptions.CredentialException;
import grisu.model.info.dto.VO;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.X509ExtensionSet;
import org.globus.gsi.bc.BouncyCastleCertProcessingFactory;
import org.globus.gsi.bc.BouncyCastleX509Extension;
import org.globus.gsi.gssapi.GSSConstants;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.globus.gsi.gssapi.GlobusGSSManagerImpl;
import org.globus.gsi.gssapi.auth.Authorization;
import org.globus.gsi.gssapi.auth.IdentityAuthorization;
import org.globus.gsi.gssapi.net.GssSocket;
import org.globus.gsi.gssapi.net.GssSocketFactory;
import org.gridforum.jgss.ExtendedGSSContext;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The actual credential that is build of a GlobusCredential and an
 * AttributeCertificate. The AttributeCertificate is sent by the VOMS server
 * after sending one of this commands:
 * 
 * <br>
 * A - this means get everything the server knows about you <br>
 * G/group - This means get group informations. /group should be /vo-name. <br>
 * This is the default request used by voms-proxy-init <br>
 * Rrole - This means grant me the specified role, in all groups in which <br>
 * you can grant it. <br>
 * Bgroup:role - This means grant me the specified role in the specified group.
 * 
 * Most of the code that does the voms magic is written by Gidon Moont from
 * Imperial College London, http://gridportal.hep.ph.ic.ac.uk/
 * 
 */
public class VomsProxyCredential {

	static final Logger myLogger = LoggerFactory.getLogger(VomsProxyCredential.class
			.getName());

	/**
	 * Static method that returns all included AttributesCertificates of a
	 * GlobusCredential. In general we are only interested in the first one.
	 * 
	 * @param vomsProxy
	 *            the voms enabled proxy credential
	 * @return all AttributeCertificates
	 */
	public static ArrayList<AttributeCertificate> extractVOMSACs(
			GlobusCredential vomsProxy) {

		// the aim of this is to retrieve all VOMS ACs
		ArrayList<AttributeCertificate> acArrayList = new ArrayList<AttributeCertificate>();

		try {

			X509Certificate[] x509s = vomsProxy.getCertificateChain();

			for (X509Certificate x509 : x509s) {

				try {

					byte[] payload = x509
							.getExtensionValue("1.3.6.1.4.1.8005.100.100.5");

					// Octet String encapsulation - see RFC 3280 section 4.1
					payload = ((ASN1OctetString) new ASN1InputStream(
							new ByteArrayInputStream(payload)).readObject())
							.getOctets();

					ASN1Sequence acSequence = (ASN1Sequence) new ASN1InputStream(
							new ByteArrayInputStream(payload)).readObject();

					for (Enumeration e1 = acSequence.getObjects(); e1
							.hasMoreElements();) {

						ASN1Sequence seq2 = (ASN1Sequence) e1.nextElement();

						for (Enumeration e2 = seq2.getObjects(); e2
								.hasMoreElements();) {

							AttributeCertificate ac = new AttributeCertificate(
									(ASN1Sequence) e2.nextElement());

							acArrayList.add(ac);

						}
					}

				} catch (Exception pe) {
					// System.out.println( "This part of the chain has no AC" )
					// ;
				}

			}

		} catch (Exception e) {
			// e.printStackTrace();
			myLogger.error("Could not extract AttributeCertificate.", e);
		}

		return acArrayList;
	}

	private GlobusCredential plainProxy = null;

	private GlobusCredential vomsProxy = null;
	private AttributeCertificate ac = null;

	private VOMSAttributeCertificate vomsac = null;
	private String command = null;
	private String order = null;

	private long lifetime = -1;

	private VO vo = null;

	/**
	 * Don't use this.
	 * 
	 * @throws Exception
	 * 
	 * @throws Exception
	 */
	// public VomsProxyCredential() throws Exception {
	// this(LocalProxy.getDefaultProxy().getGlobusCredential(), VO
	// .getDefaultVO(), "G/" + VO.getDefaultVO().getVoName(), 10000);
	// }

	public VomsProxyCredential(GlobusCredential vomsProxy) throws CredentialException {

		this.vomsProxy = vomsProxy;
		// try to extract the first attribute credential (hopefully this is the
		// voms one
		ArrayList<AttributeCertificate> acs = VomsProxyCredential.extractVOMSACs(vomsProxy);
		if ( acs.size() == 0 ) {
			throw new CredentialException("Credential is not voms enabled.");
		}
		ac = acs.get(0);
		//		if (ac == null) {
		//			throw new Exception(
		//					"Could not extract Voms attribute certificate from this globus credential. Probably this is not a voms proxy.");
		//		}

		vomsac = new VOMSAttributeCertificate(ac);
	}

	public VomsProxyCredential(GlobusCredential gridProxy,
			long lifetime_in_seconds, VO vo, String command, String order)
					throws Exception {
		this.plainProxy = gridProxy;
		this.vo = vo;
		this.command = command;
		this.order = order;
		this.lifetime = lifetime_in_seconds;
		getAC();
		generateProxy();
		vomsac = new VOMSAttributeCertificate(ac);
	}

	public VomsProxyCredential(GlobusCredential gridProxy, VO vo,
			String command, String order) throws Exception {

		this(gridProxy, gridProxy.getTimeLeft(), vo, command, order);

	}

	/**
	 * The default constructor. Assembles a VomsProxyCredential.
	 * 
	 * @deprecated Don't use this constructor anymore. Use the one that needs
	 *             seconds for lifetime...
	 * 
	 * @param gridProxy
	 *            a X509 proxy (can be the local proxy or a myproxy proxy
	 *            credential.
	 * @param vo
	 *            the VO
	 * @param command
	 *            the command to send to the VOMS server
	 * @param lifetime_in_hours
	 *            the lifetime of the proxy in hours
	 * @param order
	 *            the order
	 * @throws Exception
	 *             if something fails, obviously
	 */
	@Deprecated
	public VomsProxyCredential(GlobusCredential gridProxy, VO vo,
			String command, String order, int lifetime_in_hours)
					throws Exception {
		this.plainProxy = gridProxy;
		this.vo = vo;
		this.command = command;
		this.order = order;
		this.lifetime = lifetime_in_hours * 3600;
		getAC();
		generateProxy();
		vomsac = new VOMSAttributeCertificate(ac);
	}

	public void destroy() {
		plainProxy = null;
		vomsProxy = null;
		ac = null;
	}

	private void generateProxy() throws GeneralSecurityException {

		// Extension 1
		DERSequence seqac = new DERSequence(this.ac);
		DERSequence seqacwrap = new DERSequence(seqac);
		BouncyCastleX509Extension ace = new BouncyCastleX509Extension(
				"1.3.6.1.4.1.8005.100.100.5", seqacwrap);

		// Extension 2
		// KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature
		// | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment);
		// BouncyCastleX509Extension kue = new BouncyCastleX509Extension(
		// "2.5.29.15", keyUsage.getDERObject());

		// Extension Set
		X509ExtensionSet globusExtensionSet = new X509ExtensionSet();
		globusExtensionSet.add(ace);
		// globusExtensionSet.add(kue);

		// generate new VOMS proxy
		BouncyCastleCertProcessingFactory factory = BouncyCastleCertProcessingFactory
				.getDefault();
		vomsProxy = factory.createCredential(plainProxy.getCertificateChain(),
				plainProxy.getPrivateKey(), plainProxy.getStrength(),
				(int) plainProxy.getTimeLeft(), GSIConstants.DELEGATION_FULL,
				globusExtensionSet);

	}

	/**
	 * Contacts the VOMS server to get an AttributeCertificate
	 * 
	 * @return true if successful, false if not
	 * @throws GSSException
	 * @throws IOException
	 */
	private boolean getAC() throws GSSException, IOException {

		boolean success = false;
		int server = 0;

		myLogger.debug("Contacting VOMS server [" + vo.getHost()
				+ "] with command: " + command);

		GSSManager manager = new GlobusGSSManagerImpl();

		Authorization authorization = new IdentityAuthorization(vo.getHostDN());

		GSSCredential clientCreds = new GlobusGSSCredentialImpl(
				plainProxy, GSSCredential.INITIATE_ONLY);

		ExtendedGSSContext context = (ExtendedGSSContext) manager
				.createContext(null, GSSConstants.MECH_OID, clientCreds,
						GSSContext.DEFAULT_LIFETIME);

		context.requestMutualAuth(true);
		context.requestCredDeleg(false);
		context.requestConf(true);
		context.requestAnonymity(false);

		context.setOption(GSSConstants.GSS_MODE, GSIConstants.MODE_GSI);
		context.setOption(GSSConstants.REJECT_LIMITED_PROXY, new Boolean(false));

		GssSocket socket = (GssSocket) GssSocketFactory.getDefault()
				.createSocket(vo.getHost(), vo.getPort(), context);

		socket.setWrapMode(GssSocket.GSI_MODE);
		socket.setAuthorization(authorization);

		OutputStream out = ((Socket) socket).getOutputStream();
		InputStream in = ((Socket) socket).getInputStream();

		String msg = null;

		if ((order == null) || "".equals(order)) {
			msg = new String(
					"<?xml version=\"1.0\" encoding = \"US-ASCII\"?><voms><command>"
							+ command + "</command><lifetime>" + lifetime
							+ "</lifetime></voms>");
		} else {
			msg = new String(
					"<?xml version=\"1.0\" encoding = \"US-ASCII\"?><voms><command>"
							+ command + "</command><order>" + order
							+ "</order><lifetime>" + lifetime
							+ "</lifetime></voms>");
		}

		byte[] outToken = msg.getBytes();

		out.write(outToken);
		out.flush();

		StringBuffer voms_server_answer = new StringBuffer();

		BufferedReader buff = new BufferedReader(new InputStreamReader(in));
		char[] buf = new char[1024];
		int numRead = 0;
		while ((numRead = buff.read(buf)) != -1) {
			String readData = String.valueOf(buf, 0, numRead);
			voms_server_answer.append(readData);
			buf = new char[1024];
		}

		// String answer = buff.readLine();

		out.close();
		in.close();
		buff.close();

		String answer = voms_server_answer.toString();

		if (answer.indexOf("<error>") > 1) {
			String errormsg = answer.substring(answer.indexOf("<message>") + 9,
					answer.indexOf("</message>"));
			myLogger.warn("VOMS server returned an error => " + errormsg);
			server++;
		}

		String encoded;
		try {
			encoded = answer.substring(answer.indexOf("<ac>") + 4,
					answer.indexOf("</ac>"));
		} catch (IndexOutOfBoundsException e) {
			myLogger.warn("Could not find encoded voms proxy in server answer.");
			return success;
		}

		try {
			byte[] payload = VincenzoBase64.decode(encoded);

			ByteArrayInputStream is = new ByteArrayInputStream(payload);
			ASN1InputStream asnInStream = new ASN1InputStream(is);
			ASN1Sequence acseq = (ASN1Sequence) asnInStream.readObject();

			ac = new org.bouncycastle.asn1.x509.AttributeCertificate(acseq);

		} catch (Exception e) {
			myLogger.info(
					"Could not get AttributeCertificate: {}. Probably means the user is not member of the VO.",
					e.getLocalizedMessage());
			throw new IOException(e);
		}

		success = true;
		myLogger.debug("Success");

		return success;
	}

	public AttributeCertificate getAttributeCertificate() {
		return ac;
	}

	/**
	 * @return the voms enabled proxy
	 */
	public GlobusCredential getVomsProxy() {
		return vomsProxy;
	}

	/**
	 * Gathers information in the attribute certificate into an ArrayList
	 * 
	 * @return the equivalent of a commandline voms-proxy-info --all / null if
	 *         something's not right
	 */
	public ArrayList<String> vomsInfo() {
		ArrayList<String> info = new ArrayList<String>();
		info.add("=== VO extension information ===");
		try {
			info.add("issuer\t\t: " + vomsac.getIssuer());
			boolean checked = vomsac.verify();
			if (checked) {
				info.add("validity\t: ... signature is valid");
			} else {
				info.add("validity\t: WARNING - Unable to validate the signature of this AC - DO NOT TRUST!");
			}
			long milliseconds = vomsac.getTime();
			if (milliseconds > 0) {
				int hours = new Long(milliseconds / (1000 * 3600)).intValue();
				int minutes = new Long((milliseconds - (hours * 1000 * 3600))
						/ (1000 * 60)).intValue();
				int seconds = new Long(
						(milliseconds - ((hours * 1000 * 3600) + (minutes * 1000 * 60))) / 1000)
				.intValue();
				info.add("time left\t: " + hours + ":" + minutes + ":"
						+ seconds);
			} else {
				info.add("WARNING - this AC is not within its valid time - DO NOT TRUST!");
			}
			info.add("holder\t\t: " + vomsac.getHolder());
			info.add("version\t\t: " + vomsac.getVersion());
			info.add("algorithm\t: " + vomsac.getAlgorithmIdentifier());
			info.add("serialNumber\t: " + vomsac.getSerialNumberIntValue());
			for (String line : vomsac.getVOMSFQANs()) {
				info.add("attribute\t: " + line);
			}
			// info.addAll(vomsac.getVOMSFQANs());

		} catch (Exception e) {
			myLogger.error(e.getLocalizedMessage());
			return null;
		}
		return info;
	}

}
