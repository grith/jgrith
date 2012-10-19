package grith.jgrith.credential

import grith.jgrith.plainProxy.LocalProxy
import grisu.jcommons.constants.GridEnvironment
import grisu.jcommons.constants.Enums.LoginType
import grith.jgrith.cred.AbstractCred
import grith.jgrith.cred.MyProxyCred
import grith.jgrith.cred.ProxyCred
import grith.jgrith.cred.SLCSCred
import grith.jgrith.cred.X509Cred
import grith.jgrith.cred.callbacks.CliCallback
import grith.jgrith.cred.callbacks.StaticCallback
import grith.jgrith.plainProxy.LocalProxy

import org.globus.common.CoGProperties


class CredentialLoader {

	static Map<String, AbstractCred> loadCredentials(String pathToCredentialConfigFile) {

		File configFile = new File(pathToCredentialConfigFile)
		String configPath = configFile.getParent()

		def credConfig = new ConfigSlurper().parse(configFile.toURL())
		def credentials = [:]


		for ( def name in credConfig.keySet() ) {

			ConfigObject config = credConfig.getProperty(name)
			def typeOrig = config.get('type')
			def type = typeOrig
			if ( type instanceof String) {
				type = type.toUpperCase()

				type = LoginType.fromString(type)
			}

			switch (type) {
				case LoginType.X509_CERTIFICATE:
					AbstractCred c = loadLocal(config, configPath)
					credentials.put(name, c)
					break
				case LoginType.SHIBBOLETH:
					AbstractCred c = createSlcs(config)
					credentials.put(name, c)
					break
				case LoginType.MYPROXY:
					AbstractCred c = loadMyProxy(config)
					credentials.put(name, c)
					break
				case LoginType.LOCAL_PROXY:
					AbstractCred c = loadLocalProxy(config, configPath)
					credentials.put(name, c)
					break
				default:
					throw new RuntimeException("Type: "+typeOrig+" not available")
			}
		}
		
		return credentials
	}

	static AbstractCred loadLocalProxy(ConfigObject co, configPath) {
		def path = co.get('path')
		if ( ! path ) {
			path = LocalProxy.PROXY_FILE
		}

		File file = new File(path)
		if (! file.exists() ) {
			file = new File(configPath, file.getName())
			if ( file.exists() ) {
				throw new RuntimeException("Proxy file "+file.getAbsolutePath()+" does not exist")
			}
		}

		AbstractCred c = new ProxyCred(file.getAbsolutePath())
		return c
	}

	static AbstractCred loadMyProxy(ConfigObject co) {

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

		MyProxyCred c = new MyProxyCred(username, password.getChars(), myproxy, port)
		c.setProxyLifetimeInSeconds(lifetime*3600)

		//		c.init();
		return c
	}

	static AbstractCred createSlcs(ConfigObject co) {

		def idp = co.get('idp')
		def username = co.get('username')

		def callback = co.getAt('callback')

		SLCSCred c = new SLCSCred()
		c.setUsername(username)
		c.setIdp(idp)
		if ( ! callback ) {
			c.setCallback(new CliCallback())
		} else {
			c.setCallback(callback)
		}

		c.init()


		return c
	}

	static AbstractCred loadLocal(ConfigObject co, String configPath) {

		def cert = co.get('certificate')
		if ( ! cert ) {
			cert = CoGProperties.getDefault().getUserCertFile()
		}

		def key = co.get('key')
		if ( ! key ) {
			key = CoGProperties.getDefault().getUserKeyFile()
		}

		File certFile = new File(cert)
		if ( ! certFile.exists() ) {
			certFile = new File(configPath, certFile.getName())
			if (! certFile.exists() ) {
				throw new RuntimeException("Can't find certificate "+certFile.getAbsolutePath())
			}
			cert = certFile.getAbsolutePath()
			File keyFile = new File(configPath, new File(key).getName())
			if ( ! keyFile.exists() ) {
				throw new RuntimeException("Can't find key "+keyFile.getAbsolutePath())
			}
			key = keyFile.getAbsolutePath()
		}



		X509Cred c = new X509Cred(cert, key)
		def lifetime = co.get('lifetime')
		if ( lifetime) {
			c.setProxyLifetimeInSeconds(lifetime*3600)
		}

		def no_password = co.get('no_password')
		if ( no_password ) {
			char[] empty = new char[0]
			c.setCallback(new StaticCallback(empty))
		} else {

			def callback = co.get('callback')

			if (! callback ) {
				callback = new CliCallback()
			}

			c.setCallback(callback)
		}

		c.init()

		return c
	}


	static void main(args) {

		def creds = loadCredentials('/home/markus/src/jgrith/src/main/resources/exampleCredConfig.groovy')

		for ( c in creds.values() ) {
			print c.getDN()
			println '\t'+c.getRemainingLifetime()
		}
	}
}
