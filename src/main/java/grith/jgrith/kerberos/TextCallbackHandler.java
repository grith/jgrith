package grith.jgrith.kerberos;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class TextCallbackHandler implements CallbackHandler {

	public void handle(Callback[] callbacks) throws IOException,
	UnsupportedCallbackException {

		for (Callback callback : callbacks) {
			if (callback instanceof TextOutputCallback) {

				// display the message according to the specified type
				TextOutputCallback toc = (TextOutputCallback) callback;
				switch (toc.getMessageType()) {
				case TextOutputCallback.INFORMATION:
					System.out.println(toc.getMessage());
					break;
				case TextOutputCallback.ERROR:
					System.out.println("ERROR: " + toc.getMessage());
					break;
				case TextOutputCallback.WARNING:
					System.out.println("WARNING: " + toc.getMessage());
					break;
				default:
					throw new IOException("Unsupported message type: "
							+ toc.getMessageType());
				}

			} else if (callback instanceof NameCallback) {

				// prompt the user for a username
				NameCallback nc = (NameCallback) callback;

				// ignore the provided defaultName
				System.err.print(nc.getPrompt());
				System.err.flush();
				nc.setName((new BufferedReader(new InputStreamReader(System.in)))
						.readLine());

			} else if (callback instanceof PasswordCallback) {

				// prompt the user for sensitive information
				PasswordCallback pc = (PasswordCallback) callback;
				System.err.print(pc.getPrompt());
				System.err.flush();
				pc.setPassword(readPassword(System.in));

			} else {
				throw new UnsupportedCallbackException(callback,
						"Unrecognized Callback");
			}
		}
	}

	// // Reads user password from given input stream.
	private char[] readPassword(InputStream in) throws IOException {
		// insert code to read a user password from the input stream

		String pw = new BufferedReader(new InputStreamReader(in)).readLine();

		return pw.toCharArray();
	}

}
