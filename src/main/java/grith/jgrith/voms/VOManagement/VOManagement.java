package grith.jgrith.voms.VOManagement;

import grisu.model.info.dto.VO;
import grith.jgrith.plainProxy.LocalProxy;
import grith.jgrith.utils.CredentialHelpers;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Vector;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.globus.gsi.GlobusCredentialException;
import org.ietf.jgss.GSSCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages all VOMS servers that are of interest for the user. Information about
 * these servers can be found in the $HOME/.glite/vomses or
 * /etc/grid-security/vomsdir directory. Every file which contains a line like<br>
 * <br>
 * "Chris" "vomrsdev.vpac.org" "15003"
 * "/C=AU/O=APACGrid/OU=VPAC/CN=vomrsdev.vpac.org" "Chris" <br>
 * <br>
 * describes one VO: "Chris" is the name of the VO, followed by the hostname of
 * the VOMS server and the port the VO is mapped to. After that the DN of the
 * host of the VOMS server and I don't know what the last "Chris" means.
 * 
 * <br>
 * 
 * @author Markus Binsteiner
 * 
 */
public class VOManagement {

	static final Logger myLogger = LoggerFactory.getLogger(VOManagement.class
			.getName());

	public final static File USER_VOMSES = new File(
			System.getProperty("user.home") + File.separator + ".glite"
					+ File.separator + "vomses");

	public final static File GLOBAL_VOMSES = new File("/etc/vomses");

	public static final int MEMBER = 1;

	public static final int NO_MEMBER = 0;

	public static Vector<VO> allVOs = null;

	/**
	 * Returns the first part of the fqan (without the role/capability part)
	 * 
	 * @param cred
	 *            the credential
	 * @return the (short) fqan
	 */
	public static Map<String, VO> getAllFqans(GSSCredential cred) {
		return getAllFqans(cred, false);
	}

	/**
	 * Queries all VO servers for all of the users fqans. Returns either the
	 * full fqan or just the VO/Group part of it
	 * 
	 * @param cred
	 *            the credential
	 * @param returnWholeFqan
	 *            whether to return the full fqan (true) or not (false)
	 * @return the fqan
	 */
	public static Map<String, VO> getAllFqans(final GSSCredential cred,
			final boolean returnWholeFqan) {

		final ExecutorService executor = Executors
				.newFixedThreadPool(getAllVOs().size());

		final Map<String, VO> allFqans = Collections
				.synchronizedMap(new TreeMap<String, VO>());
		for (final VO vo : getAllVOs()) {

			Thread t = new Thread() {
				@Override
				public void run() {
					myLogger.debug("Getting all fqans for: " + vo.getVoName()
							+ "...");
					Date start = new Date();
					String[] allFqansFromThisVO = GroupManagement.getAllFqansForVO(vo,
							cred);
					// check whether user is in a vo at all
					if (allFqansFromThisVO != null) {
						for (String fqan : allFqansFromThisVO) {
							if (!returnWholeFqan) {
								// if ( "NULL".equals(GroupManagement.getRolePart(fqan))
								// ) {
								if (fqan.indexOf("/Role=") >= 0) {
									fqan = fqan.substring(0, fqan.indexOf("/Role="));
								}
								// }
							}
							allFqans.put(fqan, vo);
						}
					}
					Date end = new Date();
					myLogger.debug("Getting all fqans for: " + vo.getVoName()
							+ " took: " + (end.getTime() - start.getTime())
							+ " ms.");
				}
			};
			t.setName(vo.getVoName() + "_lookup");
			executor.execute(t);
		}

		executor.shutdown();
		try {
			executor.awaitTermination(30, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			myLogger.error("Retrieving of FQANs interrupted.", e);
		}

		return allFqans;
	}

	/**
	 * Checks every active VO for information about the user (using the provided
	 * credential) and fills in all fqans
	 * 
	 * @param gssCred
	 *            the users' credential
	 * @return a Map with all information about this user
	 */
	public static Map<VO, Map<String, Set<String>>> getAllInformationAboutUser(
			GSSCredential gssCred) {

		Map<VO, String[]> allInfoNotProcessed = new HashMap<VO, String[]>();

		for (VO vo : getAllVOs()) {
			String[] allFqans = GroupManagement.getAllFqansForVO(vo, gssCred);
			if (allFqans != null) {
				allInfoNotProcessed.put(vo, allFqans);
			}
		}

		Map<VO, Map<String, Set<String>>> allInfo = new HashMap<VO, Map<String, Set<String>>>();
		for (VO vo : allInfoNotProcessed.keySet()) {
			// get all groups
			Set<String> allGroupsOfVo = new TreeSet<String>();
			for (String fqan : allInfoNotProcessed.get(vo)) {
				allGroupsOfVo.add(GroupManagement.getGroupPart(fqan));
			}

			Map<String, Set<String>> voAllInfo = new HashMap<String, Set<String>>();
			// check all fqans again and this time sort the roles in
			for (String fqan : allInfoNotProcessed.get(vo)) {
				for (String group : allGroupsOfVo) {
					if (fqan.startsWith(group + "/Role=")) {
						if (voAllInfo.get(group) == null) {
							voAllInfo.put(group, new TreeSet<String>());
						}
						voAllInfo.get(group).add(
								GroupManagement.getRolePart(fqan));
						break;
					}
				}
			}
			allInfo.put(vo, voAllInfo);
		}

		return allInfo;
	}

	/**
	 * List of all VO's that have vomses files in $HOME/.glite/vomses or if this
	 * directory is empty in /etc/grid-security/vomsdir
	 * 
	 * @return all available VO's
	 */
	public static Vector<VO> getAllVOs() {

		if (allVOs == null) {
			Vector<VO> vos = new Vector<VO>();
			File[] files = USER_VOMSES.listFiles();

			if ((files == null) || (files.length == 0)) {
				files = GLOBAL_VOMSES.listFiles();
			}

			if (files != null) {

				for (File file : files) {
					BufferedReader f = null;
					try {
						f = new BufferedReader(new FileReader(file));
					} catch (FileNotFoundException e) {
						continue;
					}
					String line = null;
					try {
						while ((line = f.readLine()) != null) {
							VO new_vo = parseVomsesLine(line);
							if (new_vo == null) {
								continue;
							}
							vos.add(new_vo);
						}
					} catch (IOException e) {
						continue;
					}

				}
			}
			allVOs = vos;
		}
		return allVOs;
	}

	public static VO getVO(String vo_name) {

		for (VO vo : getAllVOs()) {
			if (vo_name.equals(vo.getVoName())) {
				return vo;
			}
		}
		return null;
	}

	public static void main(String[] args) {

		GSSCredential cred = null;
		try {
			cred = CredentialHelpers.wrapGlobusCredential(LocalProxy
					.loadGlobusCredential());
		} catch (GlobusCredentialException e) {
			myLogger.error(e.getLocalizedMessage());
		}

		Map<VO, Map<String, Set<String>>> allInfo = getAllInformationAboutUser(cred);

		for (VO vo : allInfo.keySet()) {
			System.out.println("VO: " + vo.getVoName());
			System.out.println("================================");
			for (String group : allInfo.get(vo).keySet()) {
				System.out.println("\n\n\tGroup: " + group);
				System.out.println("\t------------------------------");
				for (String role : allInfo.get(vo).get(group)) {
					System.out.println("\t\tRole: " + role);
				}
			}
		}

	}

	/**
	 * Takes the line that describes this VO and parses it to extract
	 * information to be able to create a VO.
	 * 
	 * @param line
	 *            the first line of a vomses file
	 * @return the according VO
	 */
	public static VO parseVomsesLine(String line) {

		int start = line.indexOf("\"") + 1;
		int end = line.indexOf("\"", start + 1);

		if ((start < 0) || (end < 0)) {
			return null;
		}

		String name = line.substring(start, end);

		start = line.indexOf("\"", end + 1) + 1;
		end = line.indexOf("\"", start + 1);

		if ((start < 0) || (end < 0)) {
			return null;
		}

		String host = line.substring(start, end);

		start = line.indexOf("\"", end + 1) + 1;
		end = line.indexOf("\"", start + 1);

		if ((start < 0) || (end < 0)) {
			return null;
		}

		int port = -1;
		try {
			port = Integer.parseInt(line.substring(start, end));
		} catch (NumberFormatException e) {
			return null;
		}
		if (port < 1) {
			return null;
		}

		start = line.indexOf("\"", end + 1) + 1;
		end = line.indexOf("\"", start + 1);

		if ((start < 0) || (end < 0)) {
			return null;
		}

		String hostDN = line.substring(start, end);

		start = line.indexOf("\"", end + 1) + 1;
		end = line.indexOf("\"", start + 1);

		// no use for that
		String stupidName = line.substring(start, end);

		start = line.indexOf("\"", end + 1) + 1;
		end = line.indexOf("\"", start + 1);

		if (start < 1) {
			myLogger.debug(name + " " + host + " " + port + " " + hostDN);

			return new VO(name, host, port, hostDN);
		}

		String vomrsUrl = line.substring(start, end);

		myLogger.debug(name + " " + host + " " + port + " " + hostDN + vomrsUrl);

		return new VO(name, host, port, hostDN);
	}


	public static void setVOsToUse(Collection<VO> vos) {
		allVOs = new Vector<VO>(vos);
	}

}
