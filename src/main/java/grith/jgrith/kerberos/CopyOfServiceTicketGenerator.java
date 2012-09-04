package grith.jgrith.kerberos;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class CopyOfServiceTicketGenerator {

	public static void main(String[] args) throws Exception {
		GSSManager manager = GSSManager.getInstance();

		Oid krb5Mechanism = new Oid("1.2.840.113554.1.2.2");
		Oid krb5PrincipalNameType = new Oid("1.2.840.113554.1.2.2.1");

		// Identify who the client wishes to be
		// GSSName userName = manager.createName("yhal003",
		// GSSName.NT_USER_NAME);

		GSSName userName = null;

		// Identify the name of the server. This uses a Kerberos specific
		// name format.
		GSSName serverName = manager.createName(
				"myproxy/myproxyca.nesi.org.nz@NESI.ORG.NZ",
				krb5PrincipalNameType);

		// Acquire credentials for the user
		GSSCredential userCreds = manager.createCredential(userName,
				GSSCredential.DEFAULT_LIFETIME, krb5Mechanism,
				GSSCredential.INITIATE_ONLY);

		// Instantiate and initialize a security context that will be
		// established with the server
		GSSContext context = manager.createContext(serverName, krb5Mechanism,
				userCreds, GSSContext.DEFAULT_LIFETIME);
	}


}
