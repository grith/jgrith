package jgrith.credential;

import static org.junit.Assert.*
import grith.jgrith.credential.Credential
import grith.jgrith.credential.MyProxyCredential
import grith.jgrith.credential.X509Credential
import grith.jgrith.credential.Credential.PROPERTY
import grith.jgrith.credential.refreshers.StaticCredentialRefresher

import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test

class CredentialTest {

	static Credential cred
	static int originalLt

	static String un1 = 'test_cred_junit'
	static char[] pw1 = 'hatr56cgj33ew;'.toCharArray()

	static String un2 = 'test_cred_junit_2'
	static char[] pw2 = 'hatr566cgj33ew;'.toCharArray()



	@BeforeClass
	public static void setUpBeforeClass() throws Exception {

		cred = new X509Credential('/home/markus/certs/test2.ceres.auckland.ac.nz_cert.pem', '/home/markus/certs/test2.ceres.auckland.ac.nz_key.pem', 'xxx'.toCharArray(), 1, true)
		originalLt = cred.getRemainingLifetime()
		StaticCredentialRefresher cr = new StaticCredentialRefresher()
		cr.addProperty(PROPERTY.Password, 'xxx'.toCharArray())
		cred.addCredentialRefreshIUI(cr)

		cred.setMyProxyDelegatedUsername(un1)
		cred.setMyProxyDelegatedPassword(pw1)



		TestUtils.deleteMyproxyCredential(cred, un1, pw1)
		TestUtils.deleteMyproxyCredential(cred, un2, pw2)
	}



	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		TestUtils.deleteMyproxyCredential(cred, un1, pw1)
		TestUtils.deleteMyproxyCredential(cred, un2, pw2)
	}

	@Before
	public void setUp() throws Exception {
		TestUtils.deleteMyproxyCredential(cred, un1, pw1)
		TestUtils.deleteMyproxyCredential(cred, un2, pw2)
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void isValid() {
		assert cred.isValid() : 'Credential not valid'
	}

	@Test
	public void testAutorefresh() {

		println 'Autorefresh'
		Thread.sleep(2000)
		int oldLt = cred.getRemainingLifetime()
		println 'Old lifetime: '+oldLt
		cred.autorefresh()
		int newLt = cred.getRemainingLifetime()
		println 'New lifetime: '+newLt

		assert newLt > oldLt : "New lifetime not longer than old one."
	}

	@Test
	public void testRefresh() {
		println 'Manual refresh'
		Thread.sleep(2000)
		int oldLt = cred.getRemainingLifetime()
		println 'Old lifetime: '+oldLt
		assert cred.refresh() : 'Refresh failed'

		int newLt = cred.getRemainingLifetime()
		println 'New lifetime: '+newLt

		assert newLt > oldLt : "New lifetime not longer than old one."
	}

	@Test
	public void testMyProxyUpload() {

		println 'MyProxy upload'

		cred.uploadMyProxy()

		MyProxyCredential delegated = new MyProxyCredential(un1, pw1, null, -1, 360000)
		println 'MyProxy lifetime: '+delegated.getRemainingLifetime()

		assert delegated.isValid()
		assertEquals("DN mismatch", cred.getDn(), delegated.getDn())
	}

	@Test
	public void testMyProxyUploadWithAutoRefresh() {

		println 'Upload with autorefresh'

		Thread.sleep(5000)

		int oldLifetime = cred.getRemainingLifetime()

		println 'Old lifetime: '+oldLifetime

		cred.autorefresh()
		int newLifetime = cred.getRemainingLifetime()
		println 'New lifetime: '+newLifetime

		MyProxyCredential delegated = new MyProxyCredential(un1, pw1, null, -1, 360000)
		int mpLifetime = delegated.getRemainingLifetime()

		println 'MyProxy lifetime: '+mpLifetime

		assert mpLifetime <= newLifetime : "MyProxy lifetime longer than initial lifetime, that can't be"
		assert mpLifetime > oldLifetime : "MyProxy lifetime not longer than old lifetime"
	}

	@Test
	public void testMyProxyUploadWithManualRefresh() {

		println 'Upload with manual refresh'

		Thread.sleep(5000)

		int oldLifetime = cred.getRemainingLifetime()

		println 'Old lifetime: '+oldLifetime

		cred.refresh()
		int newLifetime = cred.getRemainingLifetime()
		println 'New lifetime: '+newLifetime

		MyProxyCredential delegated = new MyProxyCredential(un1, pw1, null, -1, 360000)
		int mpLifetime = delegated.getRemainingLifetime()

		println 'MyProxy lifetime: '+mpLifetime

		assert mpLifetime <= newLifetime : "MyProxy lifetime longer than initial lifetime, that can't be"
		assert mpLifetime > oldLifetime : "MyProxy lifetime not longer than old lifetime"
	}

	@Test
	public void testMyProxyUploadWithRefreshAndChildren() {

		println 'Upload with auto refresh and children'

		println 'Cred lifetime: '+cred.getRemainingLifetime()

		Credential nesi = cred.getVomsCredential('/nz/nesi')

		println 'Nesi lifetime: '+nesi.getRemainingLifetime()
		nesi.setMyProxyDelegatedUsername(un2)
		nesi.setMyProxyDelegatedPassword(pw2)

		println 'Uploading nesi...'
		nesi.uploadMyProxy()
		Thread.sleep(10000)

		println 'Getting nesi...'
		MyProxyCredential nesi_delegated = new MyProxyCredential(un2, pw2, null, -1, 360000)

		int nesi_old_lifetime = nesi_delegated.getRemainingLifetime()
		TestUtils.deleteMyproxyCredential(cred, un2, pw2)
		println 'Nesi lifetime before refresh: '+nesi_old_lifetime

		assert nesi_delegated.isValid() : "Delegated VOMS MyProxy credential not valid"

		assertEquals('VO not right', nesi_delegated.getFqan(), '/nz/nesi')


		cred.autorefresh()

		nesi_delegated = new MyProxyCredential(un2, pw2, null, -1, 360000)
		int nesi_new_lifetime = nesi_delegated.getRemainingLifetime()

		println 'nesi delegated lifetime after refresh: '+nesi_new_lifetime

		assert nesi_new_lifetime > nesi_old_lifetime : "New proxy lifetime shorter than old one."
		assertEquals('VO not right', nesi_delegated.getFqan(), '/nz/nesi')
	}
}
