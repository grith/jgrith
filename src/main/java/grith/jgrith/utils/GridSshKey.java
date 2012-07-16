package grith.jgrith.utils;

import grisu.jcommons.configuration.CommonGridProperties;

import java.io.File;

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
