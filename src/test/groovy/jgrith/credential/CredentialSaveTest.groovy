package jgrith.credential;

import static org.junit.Assert.*
import grith.jgrith.credential.Credential
import grith.jgrith.credential.MyProxyCredential
import grith.jgrith.credential.X509Credential
import grith.jgrith.credential.Credential.PROPERTY
import grith.jgrith.credential.refreshers.StaticCredentialRefresher

import org.apache.commons.io.FileUtils
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test

class CredentialSaveTest {

	static Credential cred
	static int originalLt

	static String un1 = 'test_cred_junit2'
	static char[] pw1 = 'hatr56cgj33ew;'.toCharArray()

	static String un2 = 'test_cred_junit2_2'
	static char[] pw2 = 'hatr566cgj33ew;'.toCharArray()

	static String localPath = '/tmp/testProxy'

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {

		cred = new X509Credential('/home/markus/certs/test2.ceres.auckland.ac.nz_cert.pem', '/home/markus/certs/test2.ceres.auckland.ac.nz_key.pem', 'xxx'.toCharArray(), 1, true)
		originalLt = cred.getRemainingLifetime()
		StaticCredentialRefresher cr = new StaticCredentialRefresher()
		cr.addProperty(PROPERTY.Password, 'WrB0orUO'.toCharArray())
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

		FileUtils.deleteQuietly(new File(localPath))
		FileUtils.deleteQuietly(new File(localPath+'.md'))
	}

	@After
	public void tearDown() throws Exception {
	}

	public static Credential loadFromFile() {

		return Credential.loadFromMetaDataFile(localPath+".md")
	}

	@Test
	public void saveWithoutMyProxy() {

		cred.saveCredential(localPath)

		Credential newCred = loadFromFile()

		assert newCred.isUploaded() == false : 'Metadata file says proxy is uploaded where it is not'

		int oldLt = cred.getRemainingLifetime()
		int newLt = newCred.getRemainingLifetime()

		println "Old lifetime: "+oldLt
		println "New lifetime: "+newLt

		assert oldLt+2 > newLt-2 : 'Endtimes in original and loaded credentials differ too much'
	}

	@Test
	public void saveWithMyProxy() {

		cred.uploadMyProxy()

		cred.saveCredential(localPath)

		Credential newCred = loadFromFile()

		assert newCred.isUploaded() == true : 'Metadata file says proxy is not uploaded where it is'

		int oldLt = cred.getRemainingLifetime()
		int newLt = newCred.getRemainingLifetime()

		println "Old lifetime: "+oldLt
		println "New lifetime: "+newLt

		assert oldLt+2 > newLt-2 : 'Enddates of original and loaded certificates differ too much'

		MyProxyCredential delegated = new MyProxyCredential(un1, pw1)

		assert delegated.isValid()

		int del_lifetime = delegated.getRemainingLifetime()
		println 'Delegated lifetime: '+del_lifetime

		assert del_lifetime <= cred.getRemainingLifetime() : 'Delegated lifetime longer than original'
	}

	@Test
	public void saveWithAutoRefresh() {

		Thread.sleep(3000)

		int origLifetime = cred.getRemainingLifetime()

		println 'Original lifetime: '+origLifetime

		cred.saveCredential(localPath)

		cred.autorefresh()

		int newLifetime = cred.getRemainingLifetime()

		println 'New lifetime: '+origLifetime

		Credential loaded = loadFromFile()

		int loadedLifetime = loaded.getRemainingLifetime()

		println 'Loaded lifetime: '+loadedLifetime

		assert loadedLifetime > origLifetime
	}

	@Test
	public void loadWithoutProxyFile() {

		int originalLifetime = cred.getRemainingLifetime()

		println 'Original lifetime: '+originalLifetime

		cred.uploadMyProxy(true)
		cred.saveCredential(localPath)

		FileUtils.deleteQuietly(new File(localPath))

		Credential loaded = loadFromFile()

		int loadedLifetime = loaded.getRemainingLifetime()

		println 'Loaded lifetime: '+loadedLifetime
		println 'Loaded dn: '+loaded.getDn()

		assert originalLifetime >= loadedLifetime
	}

	@Test
	public void saveWithChildrenAndMyProxy() {

		Credential nesi = cred.getVomsCredential('/nz/nesi')
		cred.uploadMyProxy(true)

		nesi.setMyProxyDelegatedUsername(un2)
		nesi.setMyProxyDelegatedPassword(pw2)
		nesi.uploadMyProxy(true)

		cred.saveCredential(localPath)

		String mdfile = FileUtils.readFileToString(new File(localPath+'.md'))

		assert mdfile.contains(un2) : 'Child proxy username not in metadata file'
		assert mdfile.contains(new String(pw2)) : 'Child proxy password not in metadata file'

		MyProxyCredential delegated = new MyProxyCredential(un2, pw2)

		println 'Delegated proxy lifetime: '+delegated.getRemainingLifetime()

		assert delegated.isValid()
		assert delegated.getFqan() == '/nz/nesi'
	}

	@Test
	public void saveWithChildrenAndMyProxyWithoutProxyFile() {

		int original_lifetime = cred.getRemainingLifetime()

		Credential nesi = cred.getVomsCredential('/nz/nesi')
		cred.uploadMyProxy(true)

		nesi.setMyProxyDelegatedUsername(un2)
		nesi.setMyProxyDelegatedPassword(pw2)
		nesi.uploadMyProxy(true)

		cred.saveCredential(localPath)

		FileUtils.deleteQuietly(new File(localPath))

		String mdfile = FileUtils.readFileToString(new File(localPath+'.md'))

		assert mdfile.contains(un2) : 'Child proxy username not in metadata file'
		assert mdfile.contains(new String(pw2)) : 'Child proxy password not in metadata file'



		Credential loaded = loadFromFile()

		int loadedLifetime = loaded.getRemainingLifetime()

		println 'Loaded lifetime: '+loadedLifetime
		println 'Loaded dn: '+loaded.getDn()

		assert original_lifetime >= loadedLifetime


		Credential nesi_loaded = loaded.getVomsCredential('/nz/nesi')

		String nesi_un = nesi_loaded.getMyProxyUsername()
		char[] nesi_pw = nesi_loaded.getMyProxyPassword()

		Credential delegated = new MyProxyCredential(nesi_un, nesi_pw)

		assert delegated.isValid()

		int delegated_lifetime = delegated.getRemainingLifetime()

		println 'Delegated nesi lifetime: '+delegated_lifetime

		assert nesi_loaded.isValid()

		int nesi_loaded_lifetime = nesi_loaded.getRemainingLifetime()

		println 'Loaded nesi lifetime: '+nesi_loaded_lifetime
	}
}
