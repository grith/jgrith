package start;

import gridpp.portal.voms.VOMSAttributeCertificate;
import grith.jgrith.credential.Credential;
import grith.jgrith.credential.ProxyCredential;
import grith.jgrith.utils.CredentialHelpers;
import grith.jgrith.vomsProxy.VomsHelpers;
import grith.jgrith.vomsProxy.VomsProxyCredential;

import org.ietf.jgss.GSSCredential;

public class VomsTest {
	
	public static void main(String[] args) throws Exception {
		
		Credential c = new ProxyCredential();
		
		String defFqan = c.getFqan();
		
		System.out.println(defFqan);
		
	}

}
