package grith.jgrith.utils;

import grisu.jcommons.configuration.CommonGridProperties;

import java.io.File;
import java.io.IOException;
import java.util.Vector;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.globus.util.Util;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.KeyPair;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UserInfo;

public class GridSshKey {

	public static final int KEY_TYPE = KeyPair.RSA;

	public static GridSshKey getDefaultGridsshkey(char[] password, String id)
			throws Exception {
		return getDefaultGridsshkey(null, password, id);
	}

	public static GridSshKey getDefaultGridsshkey(char[] password)
			throws Exception {
		return getDefaultGridsshkey(null, password, null);
	}

	public static GridSshKey getDefaultGridsshkey()
			throws Exception {
		return getDefaultGridsshkey(null, null, null);
	}

	public static GridSshKey getDefaultGridsshkey(String keyPath,
			char[] password, String id) throws Exception {
		
		if ( StringUtils.isBlank(keyPath) ) {
			
			keyPath = CommonGridProperties.getDefault().getGridSSHKey();
		}
		
		if (StringUtils.isBlank(id)) {
			id = System.getProperty("user.name");
		}

		GridSshKey gsk = new GridSshKey();
		gsk.setPassword(password);
		gsk.setKeyPath(keyPath);
		gsk.setId(id);

		return gsk;
	}

	public static boolean createMobaXTermIniFile(String templatePath,
			String mobaxtermpath, String username) {

		String currentOs = System.getProperty("os.name").toUpperCase();

		if (currentOs.contains("WINDOWS")
				&& StringUtils.isNotBlank(templatePath)
				&& StringUtils.isNotBlank(mobaxtermpath)
				&& StringUtils.isNotBlank(username)) {

			MobaXtermIniCreator c = new MobaXtermIniCreator(templatePath,
					mobaxtermpath, username);

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
		panConfig.append("IdentityFile = \""
				+ CommonGridProperties.getDefault().getGridSSHKey() + "\"\n\n");

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

	public static boolean defaultGridsshkeyExists() {
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

	public static void main(String[] args) throws Exception {
		
//		GridSshKey newKey = createDefaultGridsshkey("test".toCharArray(), "markus");
//		
//		if ( true ) {
//			System.exit(1);
//		}
		
		GridSshKey gsk = new GridSshKey();
//		gsk.setPassword("test".toCharArray());

		System.out.println(gsk.exists());
		JSch jSch = new JSch();
		
		jSch.addIdentity(gsk.getKeyPath(), "test2");
		
        Session session = jSch.getSession("mbin029", "login.uoa.nesi.org.nz", 22);
        UserInfo ui = new UserInfo() {
			
			@Override
			public void showMessage(String message) {
				// TODO Auto-generated method stub
				System.out.println(message);
			}
			
			@Override
			public boolean promptYesNo(String message) {
				System.out.println(message);
				return true;
			}
			
			@Override
			public boolean promptPassword(String message) {
				// TODO Auto-generated method stub
				System.out.println(message);
				return false;
			}
			
			@Override
			public boolean promptPassphrase(String message) {
				// TODO Auto-generated method stub
				System.out.println(message);
				return false;
			}
			
			@Override
			public String getPassword() {
				// TODO Auto-generated method stub
				System.out.println("PASSWORD");
				return null;
			}
			
			@Override
			public String getPassphrase() {
				// TODO Auto-generated method stub
				System.out.println("GET PASSWORD");
				return null;
			}
		};
		
		
        session.setUserInfo(ui);
        session.connect();
        Channel channel = session.openChannel("sftp");
        ChannelSftp sftp = (ChannelSftp) channel;
        sftp.connect();

        final Vector files = sftp.ls(".");
        for (Object obj : files) {
            // Do stuff with files
        }
        sftp.disconnect();
        session.disconnect();

	}

	private String keyPath = CommonGridProperties.getDefault().getGridSSHKey();

	private char[] password;
	private String id = System.getProperty("user.name");

	public GridSshKey() {
	}

	public String getCertPath() {
		if ( StringUtils.isBlank(getKeyPath()) ) {
			return null;
		} else {
			return getKeyPath() + CommonGridProperties.CERT_EXTENSION;
					
		}
	}

	public String getId() {
		return id;
	}

	public String getKeyPath() {
		return keyPath;
	}

	public char[] getPassword() {
		return password;
	}

	public void setId(String id) {
		this.id = id;
	}

	public void setKeyPath(String certKey) {
		this.keyPath = certKey;
	}
	
	public void createIfNecessary() throws Exception {
		
		if ( exists() ) {
			return;
		}
		
		JSch jsch = new JSch();
		
		KeyPair kpair = KeyPair.genKeyPair(jsch, KEY_TYPE, 2048);
		kpair.setPassphrase(new String(password));
		kpair.writePrivateKey(getKeyPath());
		kpair.writePublicKey(getCertPath(), id);
		kpair.dispose();

		Util.setFilePermissions(CommonGridProperties.getDefault()
				.getGridSSHKey(), 600);
		Util.setFilePermissions(CommonGridProperties.getDefault()
				.getGridSSHCert(), 600);
		
	}

	public void setPassword(char[] password) {
		this.password = password;
	}

	public boolean exists() {
		if (!new File(getCertPath()).exists()) {
			return false;
		}
		if (!new File(keyPath).exists()) {
			return false;
		}

		return true;
	}

}
