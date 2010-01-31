package org.vpac.security.light;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Init {

	static final Logger myLogger = Logger.getLogger(Init.class.getName());

	public static void initBouncyCastle() {
		try {
			AccessController.doPrivileged
			(
			    new PrivilegedAction<Void>()
			    {
			       public Void run()
			       {
						// bouncy castle
						if (Security.addProvider(new BouncyCastleProvider()) == -1) {
							myLogger
									.error("Could not load BouncyCastleProvider. Makes no sense to continue...");
							System.exit(-1);
						}
			          return null;
			       }
			    }
			);
		} catch (Exception e) {
			e.printStackTrace();
			myLogger
					.error("Could not load BouncyCastleProvider. Makes no sense to continue...");
			System.exit(-1);
		}
		myLogger.info("Loaded BouncyCastleProvider.");
	}

}
