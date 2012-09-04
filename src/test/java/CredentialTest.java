import grith.jgrith.credential.Credential;
import grith.jgrith.credential.CredentialFactory;
import grith.jgrith.credential.refreshers.CliCredentialRefresher;


public class CredentialTest {

	public static void main(String[] args) {

		Credential cn = CredentialFactory.createFromCommandline();

		cn.uploadMyProxy();

		Credential voms = cn.getVomsCredential("/nz/nesi");

		voms.uploadMyProxy();

		cn.saveCredential();

		Credential c = Credential.loadFromMetaDataFile("/tmp/x509up_u1000.md");

		System.out.println(c.getRemainingLifetime());
		System.out.println(c.getFqan());

		System.out.println("Autorefresh: " + c.autorefresh());

		c.addCredentialRefreshIUI(new CliCredentialRefresher());

		System.out.println("Refresh: " + c.refresh());

		System.out.println(c.getRemainingLifetime());

	}

}
