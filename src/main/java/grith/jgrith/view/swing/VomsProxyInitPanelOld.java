package grith.jgrith.view.swing;

import grith.jgrith.plainProxy.LocalProxy;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import org.globus.gsi.GlobusCredential;
import org.ietf.jgss.GSSCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VomsProxyInitPanelOld extends JPanel implements ProxyInitListener {

	static final Logger myLogger = LoggerFactory.getLogger(VomsProxyInitPanelOld.class
			.getName());

	private JLabel createAVomsLabel;
	private JLabel createAPlainLabel;
	private static final Integer[] PREFILLS = new Integer[] { 1, 2, 3, 7, 14,
			21 };

	private VomsInfoPanel vomsInfoPanel;
	private JButton initButton;
	private JComboBox validCombobox;
	private JPasswordField passwordField;
	private JLabel validdaysLabel;
	private JLabel privateKeyPassphraseLabel;

	private DefaultComboBoxModel validModel = new DefaultComboBoxModel(PREFILLS);

	private GSSCredential credential = null;

	// -------------------------------------------------------------------
	// EventStuff
	private Vector<ProxyInitListener> proxyListeners;

	/**
	 * Create the panel
	 */
	public VomsProxyInitPanelOld() {
		super();
		final GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 7, 0, 7, 7, 7 };
		gridBagLayout.rowHeights = new int[] { 7, 7, 7, 7, 0, 7, 7, 7, 7, 7, 7,
				7, 7, 7, 7, 7, 7, 7 };
		setLayout(gridBagLayout);
		final GridBagConstraints gridBagConstraints = new GridBagConstraints();
		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.weightx = 1.0;
		gridBagConstraints.gridy = 4;
		gridBagConstraints.gridx = 1;
		final GridBagConstraints gridBagConstraints_6 = new GridBagConstraints();
		gridBagConstraints_6.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints_6.gridx = 1;
		gridBagConstraints_6.gridy = 1;
		add(getCreateAPlainLabel(), gridBagConstraints_6);
		add(getPrivateKeyPassphraseLabel(), gridBagConstraints);
		final GridBagConstraints gridBagConstraints_1 = new GridBagConstraints();
		gridBagConstraints_1.anchor = GridBagConstraints.EAST;
		gridBagConstraints_1.gridy = 4;
		gridBagConstraints_1.gridx = 3;
		add(getValiddaysLabel(), gridBagConstraints_1);
		final GridBagConstraints gridBagConstraints_2 = new GridBagConstraints();
		gridBagConstraints_2.fill = GridBagConstraints.BOTH;
		gridBagConstraints_2.gridy = 6;
		gridBagConstraints_2.gridx = 1;
		add(getPasswordField(), gridBagConstraints_2);
		final GridBagConstraints gridBagConstraints_3 = new GridBagConstraints();
		gridBagConstraints_3.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints_3.anchor = GridBagConstraints.EAST;
		gridBagConstraints_3.gridy = 6;
		gridBagConstraints_3.gridx = 3;
		add(getValidCombobox(), gridBagConstraints_3);
		final GridBagConstraints gridBagConstraints_4 = new GridBagConstraints();
		gridBagConstraints_4.anchor = GridBagConstraints.EAST;
		gridBagConstraints_4.gridy = 9;
		gridBagConstraints_4.gridx = 3;
		add(getInitButton(), gridBagConstraints_4);
		final GridBagConstraints gridBagConstraints_5 = new GridBagConstraints();
		gridBagConstraints_5.fill = GridBagConstraints.BOTH;
		gridBagConstraints_5.gridy = 16;
		gridBagConstraints_5.gridx = 1;
		gridBagConstraints_5.gridwidth = 3;
		final GridBagConstraints gridBagConstraints_7 = new GridBagConstraints();
		gridBagConstraints_7.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints_7.gridy = 13;
		gridBagConstraints_7.gridx = 1;
		add(getCreateAVomsLabel(), gridBagConstraints_7);
		add(getVomsInfoPanel(), gridBagConstraints_5);
		//
		activateOrNotVomsPanel();
	}

	private void activateOrNotVomsPanel() {
		try {
			LocalProxy.loadGlobusCredential().verify();
			getVomsInfoPanel().disablePanel(false);
			getCreateAVomsLabel().setEnabled(true);
			getVomsInfoPanel().loadCredential(LocalProxy.loadGSSCredential());
		} catch (Exception e) {
			myLogger.debug("No valid proxy here. Disabling voms panel.");
			getVomsInfoPanel().disablePanel(true);
			getCreateAVomsLabel().setEnabled(false);
		}
	}

	// register a listener
	synchronized public void addProxyListener(ProxyInitListener l) {
		if (proxyListeners == null)
			proxyListeners = new Vector();
		proxyListeners.addElement(l);
	}

	private void fireNewProxyCreated(GlobusCredential proxy) {
		// if we have no mountPointsListeners, do nothing...
		if (proxyListeners != null && !proxyListeners.isEmpty()) {
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
	protected JLabel getCreateAPlainLabel() {
		if (createAPlainLabel == null) {
			createAPlainLabel = new JLabel();
			createAPlainLabel.setText("Create a plain proxy:");
		}
		return createAPlainLabel;
	}

	/**
	 * @return
	 */
	protected JLabel getCreateAVomsLabel() {
		if (createAVomsLabel == null) {
			createAVomsLabel = new JLabel();
			createAVomsLabel.setText("Create a voms proxy");
		}
		return createAVomsLabel;
	}

	/**
	 * @return
	 */
	protected JButton getInitButton() {
		if (initButton == null) {
			initButton = new JButton();
			initButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					try {
						initProxy();
						getPasswordField().setText("");
						activateOrNotVomsPanel();
					} catch (Exception e1) {
						myLogger.error("Proxy init error: "
								+ e1.getLocalizedMessage());
						getPasswordField().setText("");
						JOptionPane.showMessageDialog(
								VomsProxyInitPanelOld.this,
								e1.getLocalizedMessage(), "Proxy init error",
								JOptionPane.ERROR_MESSAGE);
					}

				}
			});
			initButton.setText("Init");
		}
		return initButton;
	}

	/**
	 * @return
	 */
	protected JPasswordField getPasswordField() {
		if (passwordField == null) {
			passwordField = new JPasswordField();
		}
		return passwordField;
	}

	/**
	 * @return
	 */
	protected JLabel getPrivateKeyPassphraseLabel() {
		if (privateKeyPassphraseLabel == null) {
			privateKeyPassphraseLabel = new JLabel();
			privateKeyPassphraseLabel.setText("Private key passphrase");
		}
		return privateKeyPassphraseLabel;
	}

	/**
	 * @return
	 */
	protected JComboBox getValidCombobox() {
		if (validCombobox == null) {
			validCombobox = new JComboBox(validModel);
		}
		return validCombobox;
	}

	/**
	 * @return
	 */
	protected JLabel getValiddaysLabel() {
		if (validdaysLabel == null) {
			validdaysLabel = new JLabel();
			validdaysLabel.setText("Valid (days)");
		}
		return validdaysLabel;
	}

	/**
	 * @return
	 */
	protected VomsInfoPanel getVomsInfoPanel() {
		if (vomsInfoPanel == null) {
			vomsInfoPanel = new VomsInfoPanel();
			vomsInfoPanel.initialize("VomsInit", true);
			vomsInfoPanel.addVomsPanelListener(this);
		}
		return vomsInfoPanel;
	}

	private void initProxy() throws Exception {

		char[] passphrase = getPasswordField().getPassword();
		int lifetime_in_hours = ((Integer) getValidCombobox().getSelectedItem()) * 24;

		try {
			LocalProxy.gridProxyInit(passphrase, lifetime_in_hours);
		} catch (Exception e) {
			throw e;
		}

		fireNewProxyCreated(LocalProxy.loadGlobusCredential());

	}

	// this one listens to the VomsInfoPanel
	public void proxyCreated(GlobusCredential arg0) {
		fireNewProxyCreated(arg0);
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

}
