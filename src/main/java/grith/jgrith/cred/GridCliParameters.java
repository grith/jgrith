package grith.jgrith.cred;

import grisu.jcommons.constants.GridEnvironment;
import grith.jgrith.utils.CliLogin;

import org.apache.commons.lang.StringUtils;

import com.beust.jcommander.Parameter;

public class GridCliParameters {



	// @Parameter(names = { "-b", "--backend" }, description =
	// "backend to login to")
	// private String backend = LoginManagerNew.DEFAULT_BACKEND;
	// public String getBackend() {
	// return backend;
	// }

	@Parameter(names = "--nologin", description = "skip logging in")
	private boolean nologin = false;

	@Parameter(names = { "-l", "--login" }, description = "force new authentication, even if valid grid session exists")
	private boolean force = false;

	@Parameter(names = "--logout", description = "destroys a possible grid session and exits straight away")
	private boolean logout = false;

	@Parameter(names = { "-u", "--username" }, description = "institution or myproxy username")
	private String username;

	@Parameter(names = { "--institution" }, description = "institution name")
	private String institution;

	@Parameter(names = { "-m", "--myproxy_host" }, description = "myproxy host to use")
	private String myproxy_host = GridEnvironment.getDefaultMyProxyServer();

	@Parameter(names = { "-x", "--x509" }, description = "x509 certificate login")
	private boolean useX509;

	@Parameter(names = { "-s", "--start-session" }, description = "start or use existing background session to hold and update credential (on Linux)")
	private boolean startGridSession;

	@Parameter(names = { "-h", "--help" }, description = "display this help text")
	private boolean help;

	private char[] password;

	public boolean getForce() {
		return force;
	}

	public String getInstitution() {
		return institution;
	}

	public String getMyproxy_host() {
		return myproxy_host;
	}

	public char[] getPassword() {

		if (password == null) {
			return CliLogin.askPassword("Please enter the password");
		}
		return password;
	}

	public String getUsername() {
		return username;
	}

	public boolean isHelp() {
		return help;
	}

	public boolean isLogout() {
		return logout;
	}

	public boolean isNologin() {
		return nologin;
	}

	public boolean isStartGridSession() {
		return startGridSession;
	}

	public boolean useIdPLogin() {
		if (!useX509
				&& StringUtils.isNotBlank(getInstitution())
				&& StringUtils.isNotBlank(username)) {
			return true;
		} else {
			return false;
		}
	}

	public boolean useMyProxyLogin() {
		if (!useX509
				&& StringUtils.isBlank(institution)
				&& StringUtils.isNotBlank(username)) {
			return true;
		} else {
			return false;
		}
	}

	public boolean useX509Login() {
		if (useX509) {
			return true;
		} else {
			return false;
		}
	}

	public boolean valid() {
		if (((!useIdPLogin()) && (!useMyProxyLogin()) && (!useX509Login()))
				|| (useIdPLogin() && useMyProxyLogin())
				|| (useIdPLogin() && useX509Login())
				|| (useMyProxyLogin() && useX509Login())) {
			return false;
		} else {
			return true;
		}
	}


}
