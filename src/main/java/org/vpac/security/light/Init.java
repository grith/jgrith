package org.vpac.security.light;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Init {

	static final Logger myLogger = Logger.getLogger(Init.class.getName());

	public static int initBouncyCastle() {

//		System.out.println("SimpleProxyLib updated");

		try {
			AccessController.doPrivileged(new PrivilegedAction<Void>() {
				public Void run() {

					try {

						// bouncy castle
						if (Security.addProvider(new BouncyCastleProvider()) == -1) {
							myLogger.debug("Could not add BouncyCastleProvider because it is already installed.");
						}
						return null;
					} catch (Throwable e) {
						// e.printStackTrace();
						myLogger.error("Could not load BouncyCastleProvider.",
								e);
						return null;
					}
				}
			});
		} catch (Throwable e) {
			// e.printStackTrace();
			myLogger.error("Could not load BouncyCastleProvider.", e);
			// throw new RuntimeException(e);
			return -1;
		}
		myLogger.info("Loaded BouncyCastleProvider.");
		return 0;
	}

}
