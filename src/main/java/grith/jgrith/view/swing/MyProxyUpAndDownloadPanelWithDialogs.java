package grith.jgrith.view.swing;

import grith.jgrith.Environment;
import grith.jgrith.myProxy.MyProxy_light;
import grith.jgrith.utils.CredentialHelpers;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;

import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GlobusCredentialException;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class MyProxyUpAndDownloadPanelWithDialogs extends JPanel implements
ProxyInitListener {

	static final Logger myLogger = LoggerFactory.getLogger(MyProxy_light.class
			.getName());

	private JButton uploadButton;
	private JButton downloadButton;

	private GlobusCredential currentCredential = null;

	private MyProxy myproxy = null;

	// -------------------------------------------------------------------
	// EventStuff
	private Vector<ProxyInitListener> proxyListeners;

	/**
	 * Create the panel
	 */
	public MyProxyUpAndDownloadPanelWithDialogs() {
		super();
		setBorder(new TitledBorder(null, "MyProxy",
				TitledBorder.DEFAULT_JUSTIFICATION,
				TitledBorder.DEFAULT_POSITION, null, null));
		setLayout(new FormLayout(new ColumnSpec[] {
				FormFactory.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("default:grow(1.0)"),
				FormFactory.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("default:grow(1.0)"),
				FormFactory.RELATED_GAP_COLSPEC }, new RowSpec[] {
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC }));
		add(getDownloadButton(), new CellConstraints(2, 2,
				CellConstraints.LEFT, CellConstraints.DEFAULT));
		add(getUploadButton(), new CellConstraints(4, 2, CellConstraints.RIGHT,
				CellConstraints.DEFAULT));
		//
	}

	// register a listener
	synchronized public void addProxyListener(ProxyInitListener l) {
		if (proxyListeners == null) {
			proxyListeners = new Vector();
		}
		proxyListeners.addElement(l);
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
	protected JButton getDownloadButton() {
		if (downloadButton == null) {
			downloadButton = new JButton();
			downloadButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(final ActionEvent e) {

					MyProxyDownloadDialog mpdd = new MyProxyDownloadDialog();
					mpdd.initialize(Environment.getDefaultMyProxy());

					mpdd.setVisible(true);

					if (mpdd.getCred() != null) {
						fireNewProxyCreated(CredentialHelpers
								.unwrapGlobusCredential(mpdd.getCred()));
					}

				}
			});
			downloadButton.setText("Download");
		}
		return downloadButton;
	}

	/**
	 * @return
	 */
	protected JButton getUploadButton() {
		if (uploadButton == null) {
			uploadButton = new JButton();
			uploadButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(final ActionEvent e) {
					InitParams params;
					try {
						params = MyProxy_light.prepareProxyParameters(
								System.getProperty("user.name"), null, "*",
								"*", null, -1);
						MyProxyUploadDialog mpud = new MyProxyUploadDialog(
								currentCredential, params, Environment
								.getDefaultMyProxy());
						mpud.setVisible(true);

					} catch (MyProxyException e1) {
						JOptionPane
						.showMessageDialog(
								MyProxyUpAndDownloadPanelWithDialogs.this,
								"Error preparing myproxy parameters: "
										+ e1.getLocalizedMessage()
										+ "\n\n. Please contact your administrator.",
										"MyProxy error",
										JOptionPane.ERROR_MESSAGE);
					}
				}
			});
			uploadButton.setText("Upload");
			uploadButton.setEnabled(false);
		}
		return uploadButton;
	}

	@Override
	public void proxyCreated(GlobusCredential newProxy) {

		try {
			newProxy.verify();
			this.currentCredential = newProxy;
			getUploadButton().setEnabled(true);
		} catch (GlobusCredentialException e) {
			// do nothing
			myLogger.debug("Credential not valid. Not enabling upload button.");
		}
	}

	@Override
	public void proxyDestroyed() {
		this.currentCredential = null;
		getUploadButton().setEnabled(false);
	}

	// remove a listener
	synchronized public void removeProxyListener(ProxyInitListener l) {
		if (proxyListeners == null) {
			proxyListeners = new Vector<ProxyInitListener>();
		}
		proxyListeners.removeElement(l);
	}

	public void setMyproxy(MyProxy myproxy) {
		this.myproxy = myproxy;
	}

}
