package jgrith.credential

import grisu.jcommons.constants.GridEnvironment
import grith.jgrith.credential.Credential

import org.globus.myproxy.MyProxy
import org.globus.myproxy.MyProxyException

class TestUtils {
	public static deleteMyproxyCredential(Credential cred, String un, char[] pw) {
		try {
			MyProxy mp = new MyProxy(
					GridEnvironment.getDefaultMyProxyServer(),
					GridEnvironment.getDefaultMyProxyPort());
			mp.destroy(cred.getCredential(), un, new String(pw))
		} catch (MyProxyException e) {
		}
	}
}
