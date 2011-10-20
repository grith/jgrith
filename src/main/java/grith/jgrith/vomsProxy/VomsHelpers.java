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
import grith.jgrith.plainProxy.LocalProxy;
import grith.jgrith.voms.VO;
import grith.jgrith.voms.VOManagement.VOManagement;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Vector;

import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GlobusCredentialException;
import org.ietf.jgss.GSSCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VomsHelpers {

	static final Logger myLogger = LoggerFactory.getLogger(VomsHelpers.class);

	public static AttributeCertificate extractFirstAC(
			GlobusCredential globusCredential) {

		ArrayList<AttributeCertificate> acs = VomsProxyCredential
				.extractVOMSACs(globusCredential);

		if ((acs == null) || (acs.size() == 0)) {
			return null;
		} else if (acs.size() > 1) {
			myLogger.warn("More than one AttributeCertificates in the voms proxy. This is not implemented yet. Using the first one.");
		}

		return acs.get(0);
	}

	/**
	 * Retrieves all FQANs of the user from this VO.
	 * 
	 * @param vo
	 *            the VO
	 * @param credential
	 *            the users (proxy) credential
	 * @return all the users' FQANs
	 * @throws VomsException
	 *             if the voms server can't be contacted for whatever reason
	 *             (credential invalid, no network, ...)
	 */
	public static Set<String> getAllVoGroups(VO vo, GSSCredential credential)
			throws VomsException {

		try {
			GlobusCredential globusCredential = CredentialHelpers
					.unwrapGlobusCredential(credential);
			// this is a little trick to get all VO subgroups
			VomsProxyCredential tempVomsProxyCredential = new VomsProxyCredential(
					globusCredential, 60, vo, "A", null);

			Set<String> groups = getVoMemberships(tempVomsProxyCredential);
			// better to destroy the temporary credential
			tempVomsProxyCredential.destroy();
			return groups;
		} catch (Exception e1) {
			myLogger.error(e1.getLocalizedMessage(), e1);
			throw new VomsException("Could not get VO groups for VO: "
					+ vo.getVoName() + " with this credential.");
		}
	}

	/**
	 * This method gets a map of all enabled (vomses file in $HOME/.glite/vomses
	 * or /etc/grid-security/vomses) VOs the user is member and for every of
	 * this VOs the users (sub-)groups.
	 * 
	 * @param credential
	 *            the users (proxy) credential
	 * @param ignoreErrors
	 *            whether to ignore if one voms server can't be contacted or not
	 *            (recommended)
	 * @return the VO information as a Map
	 * @throws VomsException
	 * @throws VomsException
	 *             if ignoreErrors=false and the first voms server can't be
	 *             queried
	 */
	public static Map<VO, Set<String>> getAllVosAndVoGroups(
			GSSCredential credential, boolean ignoreErrors)
					throws VomsException {

		Map<VO, Set<String>> result = new TreeMap<VO, Set<String>>();

		// getting all enabled VOs (vomses files in $HOME/.glite/vomses or
		// /etc/grid-security/vomses)
		Vector<VO> allEnabledVOs = VOManagement.getAllVOs();
		// now use the credential and contact all VO servers (aka VOMS servers)
		// and
		// get all groups from each of them
		for (VO vo : allEnabledVOs) {
			try {
				Set<String> allGroups = getAllVoGroups(vo, credential);
				result.put(vo, allGroups);
			} catch (VomsException e) {
				if (ignoreErrors) {
					myLogger.error("Could not query VO: " + vo.getVoName()
							+ ". Ignoring it.");
					continue;
				} else {
					myLogger.error("Could not query VO: " + vo.getVoName()
							+ ". Exiting.");
					throw e;
				}
			}
		}

		return result;
	}

	/**
	 * Parses a vomsProxyCredential to get all the FQANs it specifies. This
	 * method removes all the role information of every FQAN.
	 * 
	 * @param vomsProxyCredential
	 *            the credential
	 * @return the FQANs
	 * @throws VomsException
	 *             if the credential can't be parsed
	 */
	public static Set<String> getVoMemberships(
			VomsProxyCredential vomsProxyCredential) throws VomsException {
		if (vomsProxyCredential == null) {
			throw new VomsException("No credential provided.");
		}
		try {
			vomsProxyCredential.getAttributeCertificate();
			List<String> fqans = new VOMSAttributeCertificate(
					vomsProxyCredential.getAttributeCertificate())
			.getVOMSFQANs();
			// remove trailing "/Role=NULL/Capability=NULL" if present
			Set<String> result = new TreeSet<String>();
			for (String s : fqans) {
				s = removeRoleAndCapabilityPart(s);
				if (!s.equals("")) {
					result.add(s);
				}
			}
			return result;
		} catch (Exception e) {
			throw new VomsException(e.getLocalizedMessage());
		}
	}

	public static void main(String[] args) throws GlobusCredentialException,
	VomsException {

		GSSCredential proxy = LocalProxy.loadGSSCredential();

		Map<VO, Set<String>> info = getAllVosAndVoGroups(proxy, true);

		for (VO vo : info.keySet()) {
			Set<String> voInfo = info.get(vo);

			System.out.println("Information for VO: " + vo.getVoName());
			System.out.println("====================================");
			System.out.println();

			for (String part : voInfo) {
				System.out.println("\tFQAN:\t" + part);
			}
		}

	}

	public static String removeRoleAndCapabilityPart(String fullFqan) {
		int pos = fullFqan.indexOf("/Role=");
		if (pos >= 0) {
			fullFqan = fullFqan.substring(0, pos);
		}
		return fullFqan;
	}
}
