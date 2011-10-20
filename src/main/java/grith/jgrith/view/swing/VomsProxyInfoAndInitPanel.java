package grith.jgrith.view.swing;

import grith.jgrith.CredentialHelpers;
import grith.jgrith.plainProxy.LocalProxy;

import java.io.File;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.globus.common.CoGProperties;
import org.globus.gsi.GlobusCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class VomsProxyInfoAndInitPanel extends JPanel implements
ProxyInitListener {

	static final Logger myLogger = LoggerFactory
			.getLogger(VomsProxyInfoAndInitPanel.class.getName());

	private VomsProxyInitPanel vomsProxyInitPanel;
	private VomsProxyInfoPanel vomsProxyInfoPanel;

	private boolean storeProxy = false;

	// -------------------------------------------------------------------
	// EventStuff
	private Vector<ProxyInitListener> proxyListeners;

	/**
	 * Create the panel
	 */
	public VomsProxyInfoAndInitPanel() {
		super();
		setLayout(new FormLayout(new ColumnSpec[] { new ColumnSpec(
				"default:grow(1.0)") }, new RowSpec[] {
				FormFactory.DEFAULT_ROWSPEC, FormFactory.RELATED_GAP_ROWSPEC,
				new RowSpec("default:grow(1.0)") }));
		add(getVomsProxyInfoPanel(), new CellConstraints(1, 1,
				CellConstraints.FILL, CellConstraints.FILL));
		add(getVomsProxyInitPanel(), new CellConstraints(1, 3,
				CellConstraints.FILL, CellConstraints.FILL));

		// getVomsProxyInitPanel().addProxyListener(getVomsProxyInfoPanel());
		// getVomsProxyInitPanel().loadPossibleLocalProxy();
		//
		getVomsProxyInitPanel().addProxyListener(this);

		addProxyListener(getVomsProxyInfoPanel());
		addProxyListener(getVomsProxyInitPanel());
	}

	// register a listener
	synchronized public void addProxyListener(ProxyInitListener l) {
		if (proxyListeners == null) {
			proxyListeners = new Vector();
		}
		proxyListeners.addElement(l);
	}

	/**
	 * If you call this method with true, every proxy that is created with the
	 * panel is stored to the default globus location.
	 * 
	 * It probably makes sense to leave that (false) and manage the writing of
	 * the proxy on your own.
	 * 
	 * @param write
	 *            whether to write a created proxy to disk (true) or not (false
	 *            -- default)
	 */
	public void enableWriteToDisk(boolean write) {
		storeProxy = write;
	}

	private void fireNewProxyCreated(GlobusCredential proxy) {
		// if we have no mountPointsListeners, do nothing...
		if ((proxyListeners != null) && !proxyListeners.isEmpty()) {
			// create the event object to send

			// make a copy of the listener list in case
			// anyone adds/removes mountPointsListeners
			Vector targets;
			synchronized (this) {
				targets = (Vector) proxyListeners.clone();
			}

			// walk through the listener list and
			// call the gridproxychanged method in each
			Enumeration e = targets.elements();
			while (e.hasMoreElements()) {
				ProxyInitListener l = (ProxyInitListener) e.nextElement();
				l.proxyCreated(proxy);
			}
		}
	}

	/**
	 * @return
	 */
	protected VomsProxyInfoPanel getVomsProxyInfoPanel() {
		if (vomsProxyInfoPanel == null) {
			vomsProxyInfoPanel = new VomsProxyInfoPanel();
		}
		return vomsProxyInfoPanel;
	}

	/**
	 * @return
	 */
	protected VomsProxyInitPanel getVomsProxyInitPanel() {
		if (vomsProxyInitPanel == null) {
			vomsProxyInitPanel = new VomsProxyInitPanel();
		}
		return vomsProxyInitPanel;
	}

	public void loadPossibleLocalProxy() {

		GlobusCredential credential = null;
		try {
			credential = LocalProxy.loadGlobusCredential();
			credential.verify();
		} catch (Exception e) {
			myLogger.debug("No valid local proxy found.");
			return;
		}
		fireNewProxyCreated(credential);
	}

	public void proxyCreated(GlobusCredential newProxy) {

		fireNewProxyCreated(newProxy);

		if (storeProxy) {
			try {
				CredentialHelpers.writeToDisk(newProxy, new File(CoGProperties
						.getDefault().getProxyFile()));
			} catch (IOException e) {
				JOptionPane.showMessageDialog(VomsProxyInfoAndInitPanel.this,
						e.getLocalizedMessage(), "Write error",
						JOptionPane.ERROR_MESSAGE);
			}
		}

	}

	public void proxyDestroyed() {
		// TODO Auto-generated method stub

	}

	// remove a listener
	synchronized public void removeProxyListener(ProxyInitListener l) {
		if (proxyListeners == null) {
			proxyListeners = new Vector<ProxyInitListener>();
		}
		proxyListeners.removeElement(l);
	}

	/**
	 * Sets the combobox that displays lifetimes
	 * 
	 * @param lifetimes
	 *            a preselection of lifetimes
	 */
	public void setLifetimeDefaults(Integer[] lifetimes) {
		getVomsProxyInitPanel().setLifetimes(lifetimes);
	}

}
