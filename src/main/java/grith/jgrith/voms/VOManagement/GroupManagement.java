package grith.jgrith.voms.VOManagement;

import gridpp.portal.voms.VOMSAttributeCertificate;
import grith.jgrith.utils.CredentialHelpers;
import grith.jgrith.voms.VO;
import grith.jgrith.vomsProxy.VomsProxyCredential;

import java.util.ArrayList;

import org.globus.gsi.GlobusCredential;
import org.ietf.jgss.GSSCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GroupManagement {

	static final Logger myLogger = LoggerFactory.getLogger(GroupManagement.class
			.getName());

	/**
	 * Returns all fqans of a user with the specified credential for the vo
	 * 
	 * @param vo
	 *            the vo you want to know the fqans for
	 * @param gssCred
	 *            the credential
	 * @return all fqans of this user for the vo or null if the user is not a
	 *         member of the VO
	 */
	public static String[] getAllFqansForVO(VO vo, GSSCredential gssCred) {

		int status = -1;
		VomsProxyCredential vomsProxy = null;

		GlobusCredential globusCredential = null;
		try {
			globusCredential = CredentialHelpers
					.unwrapGlobusCredential(gssCred);

			// create a temporary VomsProxyCredential to contact the voms server
			// and ask about all it knows about the user
			vomsProxy = new VomsProxyCredential(globusCredential, vo, "A",
					null, 1);

			if (vomsProxy.getAttributeCertificate() != null) {
				status = VOManagement.MEMBER;
			} else {
				status = VOManagement.NO_MEMBER;
			}

			if (status == VOManagement.MEMBER) {
				ArrayList<String> fqans = new VOMSAttributeCertificate(
						vomsProxy.getAttributeCertificate()).getVOMSFQANs();
				vomsProxy.destroy();
				return fqans.toArray(new String[fqans.size()]);
			} else {
				return null;
			}

		} catch (Exception e1) {
			// e1.printStackTrace();
			myLogger.debug("Error getting fqans: " + e1.getLocalizedMessage());
			status = VOManagement.NO_MEMBER;
			return null;
		}
	}

	public static String getGroupPart(String fqan) {
		return fqan.substring(0, fqan.indexOf("/Role="));
	}

	public static String getRolePart(String fqan) {
		String role = fqan.substring(fqan.indexOf("/Role=") + 6,
				fqan.indexOf("/Capability="));
		return role;
	}

	// public static String getStatusPart(String fqan) {
	// return fqan.substring(fqan.indexOf(" STATUS:")+8,
	// fqan.indexOf(" REASON:"));
	// }

}
