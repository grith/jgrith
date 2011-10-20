/* Copyright 2006 VPAC
 * 
 * This file is part of proxy_light.
 * proxy_light is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.

 * proxy_light is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with proxy_light; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package grith.jgrith.vomsProxy;

import gridpp.portal.voms.VOMSAttributeCertificate;
import grith.jgrith.CredentialHelpers;
import grith.jgrith.voms.VO;

import java.io.File;
import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GlobusCredentialException;
import org.globus.tools.proxy.DefaultGridProxyModel;
import org.ietf.jgss.GSSCredential;

/**
 * A VomsProxy is a wrapper for a {@link GlobusCredential} that has got a voms
 * attribute certificate attached to it. This class also provides all the
 * methods to easily create such a proxy in Java.
 * 
 * Internally this class uses a {@link GlobusCredential} as a kind of "base"
 * credential which will be created prior to getting the voms attribute
 * certificate. This "base" proxy is used to contact the voms server which in
 * turn will issue the attribute certificate for the group the user requested
 * (if he is a member, that is).
 * 
 * The magic happens in the classes {@link VomsProxyCredential} and
 * {@link VOMSAttributeCertificate}.
 * 
 * At the moment you only can specify the (sub-)group you want the proxy to have
 * information included. If we should need more detailed information in the
 * proxy I'll change this so that you can specify the command to the voms server
 * directly.
 * 
 * @author Markus Binsteiner
 * 
 */
public class VomsProxy {

	static final Logger myLogger = LoggerFactory.getLogger(VomsProxy.class.getName());

	/**
	 * This one creates a voms proxy with the requested vo information and
	 * returns it as GSSCredential. It's a convenience method so you don't have
	 * to create a VomsProxy wrapper object if you don't need to.
	 * 
	 * @param vo
	 *            the vo you want to have the proxy for
	 * @param group
	 *            the group you want to have the proxy for (example:
	 *            /APACGrid/NGAdmin)
	 * @param passphrase
	 *            the passphrase of your local private key
	 * @param lifetime_in_hours
	 *            how long the proxy should be valid
	 * @throws Exception
	 *             if something went wrong
	 */
	public static GSSCredential init(VO vo, String group, char[] passphrase,
			int lifetime_in_hours) throws Exception {

		VomsProxy vomsproxy = null;
		try {
			vomsproxy = new VomsProxy(vo, group, passphrase,
					lifetime_in_hours * 3600 * 1000);
		} catch (Exception e) {
			LocalVomsProxy.myLogger.error("Could not create voms proxy: "
					+ e.getMessage());
			throw e;
		}

		if (vomsproxy == null || vomsproxy.getVomsProxyCredential() == null) {
			LocalVomsProxy.myLogger.error("Voms proxy is null.");
			throw new NullPointerException(
					"VomsProxy or VomsProxyCredentail is null.");
		}

		try {
			vomsproxy.getVomsProxyCredential().verify();
		} catch (GlobusCredentialException e) {
			LocalVomsProxy.myLogger.error("Voms proxy is not valid: "
					+ e.getMessage());
			throw e;
		}

		return CredentialHelpers.wrapGlobusCredential(vomsproxy
				.getVomsProxyCredential());
	}

	public static boolean isVomsProxy(GlobusCredential cred) {

		try {
			new VomsProxy(cred);
		} catch (Exception e) {
			return false;
		}
		return true;
	}

	private VO vo = null;
	private String command = null;

	private String order = null;
	private long lifetime_in_ms = -1;
	private GlobusCredential baseProxy = null;

	private VomsProxyCredential vomsProxyCredential = null;

	private AttributeCertificate ac = null;

	private ArrayList<String> vomsInfo = null;

	/**
	 * Creates a VomsProxy by parsing a file that contains a voms-enabled X509
	 * proxy.
	 * 
	 * @param proxyFile
	 *            the proxy file
	 * @throws NoVomsProxyException
	 *             if the proxy is not a voms proxy
	 */
	public VomsProxy(File proxyFile) throws Exception {

		try {
			// not really the base proxy, but who cares...
			baseProxy = CredentialHelpers.loadGlobusCredential(proxyFile);
			baseProxy.verify();
		} catch (Exception e) {
			myLogger.error("Could not load valid credential from file \""
					+ proxyFile.toString() + "\": " + e.getMessage());
		}
		vomsProxyCredential = new VomsProxyCredential(baseProxy);

	}

	public VomsProxy(GlobusCredential credential) throws Exception {
		// not really the base proxy, but who cares...
		baseProxy = credential;
		baseProxy.verify();

		vomsProxyCredential = new VomsProxyCredential(baseProxy);
	}

	/**
	 * This creates a VomsProxy using usercert.pem and userkey.pem in the
	 * default globus location to create a intermediate proxy that is used to
	 * attach the voms attribute certificate to. You have to provide the
	 * passphrase of the private key.
	 * 
	 * @param vo
	 *            the vo you want to have the proxy for
	 * @param group
	 *            the group you want to have the proxy for (example:
	 *            /APACGrid/NGAdmin)
	 * @param passphrase
	 *            the passphrase of the private key
	 * @param lifetime_in_ms
	 *            the lifetime of the proxy (and the voms attribute certificate)
	 *            in milliseconds
	 * @throws Exception
	 */
	public VomsProxy(VO vo, String group, char[] passphrase, long lifetime_in_ms)
			throws Exception {

		this.vo = vo;
		this.lifetime_in_ms = lifetime_in_ms;
		// this is the command that is sent to the voms server
		// possible commands:
		// A - This means get everything the server knows about you
		// G/group - This means get group informations. /group should be
		// /vo-name.
		// This is the default request used by voms-proxy-init
		// Rrole - This means grant me the specified role, in all groups in
		// which you can grant it.
		// Bgroup:role - This means grant me the specified role in the specified
		// group.
		this.command = "G" + group;
		this.order = group;
		// create the proxy now
		try {
			createDefaultBaseProxy(passphrase, this.lifetime_in_ms);
		} catch (Exception e) {
			myLogger.error("Could not create base proxy: " + e.getMessage());
			throw e;
		}

		try {
			// create the voms attribute certificate
			createAttributeCertificate(baseProxy, this.vo, this.lifetime_in_ms);
		} catch (Exception e) {
			myLogger.error("Could not create voms attribute certificate: "
					+ e.getMessage());
			throw e;
		}

	}

	/**
	 * Creates a VomsProxy using the {@link GlobusCredential} you provide. The
	 * constructor tries to contact the voms server and get an attribute
	 * certificate for the requested VO/group and then attaches this attribute
	 * certificate to the {@link GlobusCredential}.
	 * 
	 * Use getVomsProxyCredential() to get the actual voms proxy.
	 * 
	 * @param vo
	 *            the VO you want the proxy forprivate
	 * @param group
	 *            the (sub-)group within the VO you want the proxy for (example:
	 *            /APACGrid/NGAdmin)
	 * @param baseProxy
	 *            a valid GlobusCredential (with the appropriate dn the voms
	 *            server has in it's database)
	 * @param lifetime_in_ms
	 *            the lifetime of the proxy (and the voms attribute certificate)
	 *            in milliseconds
	 * @throws Exception
	 *             if somethings gone wrong
	 */
	public VomsProxy(VO vo, String group, GlobusCredential baseProxy,
			long lifetime_in_ms) throws Exception {

		this.vo = vo;
		this.lifetime_in_ms = lifetime_in_ms;
		// this is the command that is sent to the voms server
		// possible commands:
		// A - This means get everything the server knows about you
		// G/group - This means get group informations. /group should be
		// /vo-name.
		// This is the default request used by voms-proxy-init
		// Rrole - This means grant me the specified role, in all groups in
		// which you can grant it.
		// Bgroup:role - This means grant me the specified role in the specified
		// group.
		this.command = "G" + group;
		this.order = group;

		try {
			// check whether the base proxy is valid, if not: break
			baseProxy.verify();
		} catch (GlobusCredentialException e) {
			myLogger.error("Can't create Voms attribute certificate because base proxy is not valid: "
					+ e.getMessage());
			throw new Exception(
					"Can't create Voms attribute certificate because base proxy is not valid: "
							+ e.getMessage());
		}

		try {
			// create the voms attribute certificate
			createAttributeCertificate(baseProxy, this.vo, this.lifetime_in_ms);
		} catch (Exception e) {
			myLogger.error("Could not create voms attribute certificate: "
					+ e.getMessage());
			throw e;
		}
	}

	private void createAttributeCertificate(GlobusCredential baseCred, VO vo,
			long lifetime_in_ms) throws Exception {

		// create the VomsProxyCredential
		vomsProxyCredential = new VomsProxyCredential(baseCred, vo, command,
				order, new Long(lifetime_in_ms / 1000).intValue());
		// hm. something went wrong
		// myLogger.error("Could not create AttributeCertificate: "+e.getMessage());

		// check whether the vomsProxyCredential really was created
		if (this.vomsProxyCredential == null) {
			throw new Exception("Voms attribute certificate is null.");
		}
		vomsInfo = null;

	}

	/**
	 * Create a "plain" GlobusCredential first which is used to attach the VOMS
	 * Attribute certificate to
	 * 
	 * @param passphrase
	 *            the passphrase of the private key
	 * @param lifetime_in_ms
	 *            the lifetime of the proxy in milliseconds
	 * @return true if the creation of the proxy worked, wrong if not
	 * @throws Exception
	 */
	private void createDefaultBaseProxy(char[] passphrase, long lifetime_in_ms)
			throws Exception {

		// get the default model for local proxies
		DefaultGridProxyModel model = new DefaultGridProxyModel();
		// the the lifetime of the "base" GlobusCredential
		model.getProperties().setProxyLifeTime(
				new Long((lifetime_in_ms) / (1000 * 3600)).intValue());
		// create the "base" GlobusCredential
		this.baseProxy = model.createProxy(new String(passphrase));

	}

	/**
	 * Returns the default fqan of this voms proxy.
	 * 
	 * @param fullString
	 *            whether you want the full String or only VO and group
	 * @return the default fqan or null if it couldn't be established.
	 */
	public String getDefaultFqan(boolean fullString) {
		if (vomsProxyCredential == null) {
			return null;
		}
		try {
			VOMSAttributeCertificate vomsac = new VOMSAttributeCertificate(
					vomsProxyCredential.getAttributeCertificate());

			String defFqan = vomsac.getVOMSFQANs().get(0);

			if (fullString) {
				return defFqan;
			} else {
				return VomsHelpers.removeRoleAndCapabilityPart(defFqan);
			}
		} catch (Exception e) {
			myLogger.error("Couldn't get default fqan of VomsProxy: "
					+ e.getLocalizedMessage());
			return null;
		}

	}

	/**
	 * Retrieves information from the {@link VOMSAttributeCertificate}
	 * 
	 * @return output similar to the commandline voms-proxy-info
	 */
	public ArrayList<String> getVomsInfo() {

		if (vomsInfo == null) {
			vomsInfo = vomsProxyCredential.vomsInfo();
		}

		return vomsInfo;
	}

	/**
	 * If not null, this one returns the actual voms proxy credential
	 * 
	 * @return the {@link GlobusCredential} with the attached voms attribute
	 *         certificate or null if something went wrong during creation
	 */
	public GlobusCredential getVomsProxyCredential() {
		if (vomsProxyCredential == null) {
			return null;
		}
		return vomsProxyCredential.getVomsProxy();
	}

}
