package grith.jgrith.credential

import grisu.jcommons.constants.GridEnvironment
import grith.jgrith.plainProxy.LocalProxy
import grith.jgrith.utils.CliLogin


class CredentialLoader {

	static Map loadCredentials(String pathToCredentialConfigFile) {

		def credConfig = new ConfigSlurper().parse(new File(pathToCredentialConfigFile).toURL())
		def credentials = [:]
		for ( def name in credConfig.keySet() ) {

			ConfigObject config = credConfig.getProperty(name)
			def type = config.get('login_type')

			switch (type) {
				case 'x509':
					Credential c = loadLocal(config)
					credentials.put(name, c)
					break
				case 'shib':
					Credential c = createSlcs(config)
					credentials.put(name, c)
					break
				case 'myproxy':
					Credential c = loadMyProxy(config)
					credentials.put(name, c)
					break
				case 'proxy':
					Credential c = loadLocalProxy(config)
					credentials.put(name, c)
					break
				default:
					print 'default'
			}
		}
		return credentials
	}

	static Credential loadLocalProxy(ConfigObject co) {
		def path = co.get('path')
		if ( ! path ) {
			path = LocalProxy.PROXY_FILE
		}
		Credential c = new ProxyCredential(path)
		return c
	}

	static Credential loadMyProxy(ConfigObject co) {

		def username = co.get('username')
		def password = co.get('password')
		def myproxy = co.get('host')
		def port = co.get('port')
		def lifetime = co.get('lifetime')
		if ( ! lifetime ) {
			lifetime = 12
		}
		if ( ! myproxy ) {
			myproxy = GridEnvironment.getDefaultMyProxyServer()
		}
		if ( ! port ) {
			port = GridEnvironment.getDefaultMyProxyPort()
		}

		Credential c = CredentialFactory.createFromMyProxy(username, password.getChars(), myproxy, port, lifetime*3600)
		return c
	}

	static Credential createSlcs(ConfigObject co) {

		def idp = co.get('idp')
		def username = co.get('username')

		println "Using user '"+username+"' at '"+idp+"'..."

		char[] pw = CliLogin
				.askPassword("Please enter institution password")

		Credential c = CredentialFactory.createFromSlcs(null, idp, username, pw, -1)

		return c
	}

	static Credential loadLocal(ConfigObject co) {

		def cert = co.get('certificate')
		def key = co.get('key')
		def passphrase = co.get('passphrase')

		def lifetime = co.get('lifetime')

		Credential c = new X509Credential(cert, key, passphrase.toCharArray(), lifetime, true)

		return c
	}


	static void main(args) {

		def creds = loadCredentials('/home/markus/src/jgrith/src/main/resources/exampleCredConfig.groovy')

		for ( c in creds ) {
			print c.getDn()
			println '\t'+c.getRemainingLifetime()
		}
	}
}
