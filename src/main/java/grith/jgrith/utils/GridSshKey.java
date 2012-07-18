package grith.jgrith.utils;

import grisu.jcommons.configuration.CommonGridProperties;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.globus.util.Util;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.KeyPair;

public class GridSshKey {

	public static final int KEY_TYPE = KeyPair.RSA;

	public static void createGridsshkey(char[] password, String id)
			throws Exception {

		if (gridsshkeyExists()) {
			throw new Exception("Key and/or Cert file(s) already exist.");
		}

		JSch jsch = new JSch();
		KeyPair kpair = KeyPair.genKeyPair(jsch, KEY_TYPE);
		kpair.setPassphrase(new String(password));
		kpair.writePrivateKey(CommonGridProperties.getDefault().getGridSSHKey());
		kpair.writePublicKey(
				CommonGridProperties.getDefault().getGridSSHCert(), id);
		kpair.dispose();

		Util.setFilePermissions(CommonGridProperties.getDefault()
				.getGridSSHKey(), 600);
		Util.setFilePermissions(CommonGridProperties.getDefault()
				.getGridSSHCert(), 600);
	}

	public static boolean createMobaXTermIniFile(String templatePath,
			String mobaxtermpath, String username) {

		String currentOs = System.getProperty("os.name")
				.toUpperCase();

		if (currentOs.contains("WINDOWS")
				&& StringUtils.isNotBlank(templatePath)
				&& StringUtils.isNotBlank(mobaxtermpath)
				&& StringUtils.isNotBlank(username)) {


			MobaXtermIniCreator c = new MobaXtermIniCreator(
					templatePath, mobaxtermpath, username);

			c.create();
			return true;
		}
		return false;
	}

	public static boolean createSSHConfigFile(String username) {

		String sshconfigpath = CommonGridProperties.SSH_DIR + File.separator
				+ "config";

		StringBuffer panConfig = new StringBuffer("\nHost pan\n");
		panConfig.append("\nHostName login.uoa.nesi.org.nz\n");
		panConfig.append("User " + username + "\n");
		panConfig.append("IdentityFile = "
				+ CommonGridProperties.getDefault().getGridSSHKey() + "\n\n");

		File sshconfig = new File(sshconfigpath);
		try {
			if (sshconfig.exists()) {

				String oldConfig = FileUtils.readFileToString(sshconfig);
				if ((oldConfig != null)
						&& oldConfig.contains("login.uoa.nesi.org.nz")) {

					// already has got an entry
					return false;
				}
				FileUtils.write(sshconfig, panConfig, true);
				return true;

			} else {
				FileUtils.write(sshconfig, panConfig);
				return true;
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

	}

	public static boolean gridsshkeyExists() {
		File key = new File(CommonGridProperties.getDefault().getGridSSHKey());
		if (!key.exists()) {
			return false;
		}
		File cert = new File(CommonGridProperties.getDefault().getGridSSHCert());
		if (!cert.exists()) {
			return false;
		}
		return true;
	}


	public GridSshKey() throws Exception {
		super();
	}




}
