package grith.jgrith.kerberos;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class ServiceTicketGenerator implements
PrivilegedExceptionAction<byte[]> {

	public static void main(String[] args) throws Exception {
		System.setProperty("java.security.auth.login.config",
				"/home/markus/src/jgrith/src/main/resources/login.conf");

		// create a LoginContext based on the entry in the login.conf file
		LoginContext lc = new LoginContext("SignedOnUserLoginContext",
				new TextCallbackHandler());


		// login (effectively populating the Subject)
		lc.login();

		// get the Subject that represents the signed-on user
		Subject clientSubject = lc.getSubject();
		byte[] serviceTicket = Subject.doAs(clientSubject,
				new ServiceTicketGenerator());
	}

	public byte[] run() throws Exception {
		try {
			// GSSAPI is generic, but if you give it the following Object ID,
			// it will create Kerberos 5 service tickets
			Oid kerberos5Oid = new Oid("1.2.840.113554.1.2.2");

			// create a GSSManager, which will do the work
			GSSManager gssManager = GSSManager.getInstance();

			// tell the GSSManager the Kerberos name of the client and service
			// (substitute your appropriate names here)
			GSSName clientName = gssManager.createName("yhal003@NESI.ORG.NZ",
					GSSName.NT_USER_NAME);
			GSSName serviceName = gssManager.createName(
					"myproxy@myproxyca.nesi.org.nz@NESI.ORG.NZ", null);

			// get the client's credentials. note that this run() method was
			// called by Subject.doAs(),
			// so the client's credentials (Kerberos TGT or Ticket-Granting
			// Ticket) are already available in the Subject
			GSSCredential clientCredentials = gssManager.createCredential(
					clientName, 8 * 60 * 60, kerberos5Oid,
					GSSCredential.INITIATE_ONLY);

			// create a security context between the client and the service
			GSSContext gssContext = gssManager.createContext(serviceName,
					kerberos5Oid, clientCredentials,
					GSSContext.DEFAULT_LIFETIME);

			// initialize the security context
			// this operation will cause a Kerberos request of Active Directory,
			// to create a service ticket for the client to use the service
			byte[] serviceTicket = gssContext.initSecContext(new byte[0], 0, 0);
			gssContext.dispose();

			// return the Kerberos service ticket as an array of encrypted bytes
			return serviceTicket;
		} catch (Exception ex) {
			throw new PrivilegedActionException(ex);
		}
	}
}
