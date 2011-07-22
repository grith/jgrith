package grith.jgrith.control;

import java.util.Enumeration;
import java.util.TimerTask;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GlobusCredentialException;

public class CredentialStatusTimerTask extends TimerTask {

	static final Logger myLogger = Logger
			.getLogger(CredentialStatusTimerTask.class.getName());

	private GlobusCredential proxy = null;

	// ---------------------------------------------------------------------------------------
	// Event stuff (MountPoints)
	private Vector<CredentialStatusListener> mountPointsListeners;

	public CredentialStatusTimerTask(GlobusCredential proxy) {
		this.proxy = proxy;
	}

	// register a listener
	synchronized public void addCredentialStatusListener(
			CredentialStatusListener l) {
		if (mountPointsListeners == null) {
			mountPointsListeners = new Vector<CredentialStatusListener>();
		}
		mountPointsListeners.addElement(l);
	}

	private void fireCredentialStatusEvent(GlobusCredential credential, int type) {
		// if we have no credentialListeners, do nothing...
		if ((mountPointsListeners != null) && !mountPointsListeners.isEmpty()) {
			// create the event object to send
			CredentialStatusEvent event = null;
			event = new CredentialStatusEvent(credential, type);

			Vector<CredentialStatusListener> targets;
			synchronized (this) {
				targets = (Vector<CredentialStatusListener>) mountPointsListeners
						.clone();
			}

			Enumeration<CredentialStatusListener> e = targets.elements();
			while (e.hasMoreElements()) {
				CredentialStatusListener l = e.nextElement();
				try {
					l.credentialStatusChanged(event);
				} catch (Exception e1) {
					myLogger.error(e1);
				}
			}
		}
	}

	// remove a listener
	synchronized public void removeCredentialStatusListener(
			CredentialStatusListener l) {
		if (mountPointsListeners == null) {
			mountPointsListeners = new Vector<CredentialStatusListener>();
		}
		mountPointsListeners.removeElement(l);
	}

	@Override
	public void run() {
		try {
			proxy.verify();
		} catch (GlobusCredentialException e) {
			fireCredentialStatusEvent(proxy,
					CredentialStatusEvent.CREDENTIAL_EXPIRED);
			mountPointsListeners.removeAllElements();
			this.cancel();
		}
		fireCredentialStatusEvent(proxy,
				CredentialStatusEvent.CREDENTIAL_TIME_REMAINING_CHANGED);
	}

}
