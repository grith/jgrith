package grith

import grisu.jcommons.exceptions.CredentialException
import grith.jgrith.credential.Credential
import grith.jgrith.credential.CredentialFactory

class ProxyRefresher {

	static main(args) {

		int initialLifetime = 12 * 3600
		int minLifetime = initialLifetime - 50

		Credential cred = CredentialFactory.createFromCommandline(12)

		int lifetime = cred.getRemainingLifetime()
		if ( lifetime < minLifetime ) {
			throw new CredentialException("Can't create credential with at least minimum lifetime of "+minLifetime+" seconds")
		}
		cred.setMinimumLifetime(minLifetime)

		cred.setMinTimeBetweenAutoRefreshes(20)

		while (true) {
			def remaining = cred.getRemainingLifetime()
			println 'remaining: '+remaining
			Thread.sleep(5000)
		}
	}
}
