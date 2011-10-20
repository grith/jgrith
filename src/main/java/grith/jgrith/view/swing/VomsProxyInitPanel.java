package grith.jgrith.view.swing;

import grith.jgrith.CredentialHelpers;
import grith.jgrith.plainProxy.PlainProxy;
import grith.jgrith.voms.VO;
import grith.jgrith.voms.VOManagement.VOManagement;
import grith.jgrith.vomsProxy.VomsException;
import grith.jgrith.vomsProxy.VomsProxy;

import java.awt.Cursor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Map;
import java.util.Vector;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.border.TitledBorder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.globus.gsi.GlobusCredential;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class VomsProxyInitPanel extends JPanel implements ProxyInitListener {

	static final Logger myLogger = LoggerFactory.getLogger(VomsProxyInitPanel.class
			.getName());

	public static final String NON_VOMS_PROXY_NAME = "None";

	private JButton voButton;
	private JButton initButton;
	private JComboBox voComboBox;
	private JComboBox lifetimeComboBox;
	private JPasswordField passwordField;
	private JLabel label_2;
	private JLabel label_1;
	private JLabel label;

	public static final Integer[] DEFAULT_LIFETIMES = new Integer[] { 1, 2, 3,
		7, 14, 21 };
	public static final String DEFAULT_TITLE = "Update";

	private final DefaultComboBoxModel lifetimeModel = new DefaultComboBoxModel(
			DEFAULT_LIFETIMES);
	private final DefaultComboBoxModel voModel = new DefaultComboBoxModel();

	private GlobusCredential credential = null;
	private VomsProxy currentVomsProxy = null;
	// Map<VO, Set<String>> info = null;

	Map<String, VO> allFqans = null;

	boolean ignoreErrors = true;

	// -------------------------------------------------------------------
	// EventStuff
	private Vector<ProxyInitListener> proxyListeners;

	/**
	 * Create the panel
	 */
	public VomsProxyInitPanel() {
		super();
		setBorder(DEFAULT_TITLE);
		setLayout(new FormLayout(new ColumnSpec[] {
				FormFactory.RELATED_GAP_COLSPEC, new ColumnSpec("65dlu"),
				FormFactory.RELATED_GAP_COLSPEC,
				new ColumnSpec("25dlu:grow(1.0)"),
				FormFactory.RELATED_GAP_COLSPEC, FormFactory.DEFAULT_COLSPEC,
				FormFactory.RELATED_GAP_COLSPEC }, new RowSpec[] {
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC }));
		add(getLabel(), new CellConstraints(2, 2));
		add(getLabel_1(), new CellConstraints(2, 4));
		add(getLabel_2(), new CellConstraints(2, 6));
		add(getPasswordField(), new CellConstraints(4, 2, 3, 1));
		add(getLifetimeComboBox(), new CellConstraints(4, 4));
		add(getVoComboBox(), new CellConstraints(4, 6));
		add(getInitButton(), new CellConstraints(6, 4));
		add(getVoButton(), new CellConstraints(6, 6));
		//

	}

	// register a listener
	synchronized public void addProxyListener(ProxyInitListener l) {
		if (proxyListeners == null) {
			proxyListeners = new Vector();
		}
		proxyListeners.addElement(l);
	}

	private void fillVOs() throws VomsException {

		String oldFqan = (String) getVoComboBox().getSelectedItem();

		voModel.removeAllElements();
		//
		// voModel.addElement(NON_VOMS_PROXY_NAME);

		allFqans = VOManagement.getAllFqans(CredentialHelpers
				.wrapGlobusCredential(credential));

		for (String fqan : allFqans.keySet()) {
			voModel.addElement(fqan);
		}

		if (voModel.getIndexOf(oldFqan) >= 0) {
			voModel.setSelectedItem(oldFqan);
		}
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
	protected JButton getInitButton() {
		if (initButton == null) {
			initButton = new JButton();
			initButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					new Thread() {
						@Override
						public void run() {
							try {
								VomsProxyInitPanel.this.setCursor(Cursor
										.getPredefinedCursor(Cursor.WAIT_CURSOR));
								getInitButton().setEnabled(false);
								getVoButton().setEnabled(false);
								initProxy();
							} catch (Exception e) {
								VomsProxyInitPanel.this.setCursor(Cursor
										.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
								myLogger.error("Proxy init error: "
										+ e.getLocalizedMessage());
								getPasswordField().setText("");
								JOptionPane.showMessageDialog(
										VomsProxyInitPanel.this,
										e.getLocalizedMessage(),
										"Proxy init error",
										JOptionPane.ERROR_MESSAGE);
								return;
							} finally {
								VomsProxyInitPanel.this.setCursor(Cursor
										.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
								getPasswordField().setText("");
								getInitButton().setEnabled(true);
								getVoButton().setEnabled(true);
							}
						}
					}.start();

				}
			});
			initButton.setText("Authenticate");
		}
		return initButton;
	}

	/**
	 * @return
	 */
	protected JLabel getLabel() {
		if (label == null) {
			label = new JLabel();
			label.setText("Enter passphrase");
		}
		return label;
	}

	/**
	 * @return
	 */
	protected JLabel getLabel_1() {
		if (label_1 == null) {
			label_1 = new JLabel();
			label_1.setText("Lifetime (days)");
		}
		return label_1;
	}

	/**
	 * @return
	 */
	protected JLabel getLabel_2() {
		if (label_2 == null) {
			label_2 = new JLabel();
			label_2.setText("Available VOs");
		}
		return label_2;
	}

	/**
	 * @return
	 */
	protected JComboBox getLifetimeComboBox() {
		if (lifetimeComboBox == null) {
			lifetimeComboBox = new JComboBox(lifetimeModel);
		}
		return lifetimeComboBox;
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
	protected JButton getVoButton() {
		if (voButton == null) {
			voButton = new JButton();
			voButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					new Thread() {
						@Override
						public void run() {
							try {
								VomsProxyInitPanel.this.setCursor(Cursor
										.getPredefinedCursor(Cursor.WAIT_CURSOR));
								getInitButton().setEnabled(false);
								getVoButton().setEnabled(false);

								String fqan = (String) getVoComboBox()
										.getSelectedItem();

								// if (NON_VOMS_PROXY_NAME.equals(fqan)) {
								//
								// VomsProxy temp = new VomsProxy(credential);
								//
								// } else {

								VO vo = allFqans.get(fqan);
								long lifetime;

								lifetime = CredentialHelpers
										.wrapGlobusCredential(credential)
										.getRemainingLifetime() * 1000;
								currentVomsProxy = new VomsProxy(vo, fqan,
										credential, lifetime);

								fireNewProxyCreated(currentVomsProxy
										.getVomsProxyCredential());
								// }

							} catch (Exception e) {
								VomsProxyInitPanel.this.setCursor(Cursor
										.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
								JOptionPane.showMessageDialog(
										VomsProxyInitPanel.this,
										e.getLocalizedMessage(), "Voms error",
										JOptionPane.ERROR_MESSAGE);
								return;
							} finally {
								VomsProxyInitPanel.this.setCursor(Cursor
										.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
								getPasswordField().setText("");
								getInitButton().setEnabled(true);
								getVoButton().setEnabled(true);

							}
						}

					}.start();
				}
			});
			voButton.setText("Add Group");
		}
		return voButton;
	}

	/**
	 * @return
	 */
	protected JComboBox getVoComboBox() {
		if (voComboBox == null) {
			voComboBox = new JComboBox(voModel);
		}
		return voComboBox;
	}

	private void initProxy() throws Exception {

		char[] passphrase = getPasswordField().getPassword();
		int lifetime_in_hours = ((Integer) getLifetimeComboBox()
				.getSelectedItem()) * 24;

		try {
			credential = CredentialHelpers.unwrapGlobusCredential(PlainProxy
					.init(passphrase, lifetime_in_hours));
		} catch (Exception e) {
			throw e;
		}

		fireNewProxyCreated(credential);

	}

	public void proxyCreated(GlobusCredential proxy) {

		this.credential = proxy;

		try {
			credential.verify();
			getVoButton().setEnabled(true);
			getVoComboBox().setEnabled(true);
			fillVOs();
		} catch (Exception e) {
			myLogger.debug("No valid proxy here. Disabling voms panel.");
			getVoButton().setEnabled(false);
			getVoComboBox().setEnabled(false);
			voModel.removeAllElements();
		}
	}

	public void proxyDestroyed() {

		proxyCreated(null);

	}

	// remove a listener
	synchronized public void removeProxyListener(ProxyInitListener l) {
		if (proxyListeners == null) {
			proxyListeners = new Vector<ProxyInitListener>();
		}
		proxyListeners.removeElement(l);
	}

	public void setBorder(String title) {
		setBorder(new TitledBorder(null, title,
				TitledBorder.DEFAULT_JUSTIFICATION,
				TitledBorder.DEFAULT_POSITION, null, null));
	}

	public void setLifetimes(Integer[] values) {
		lifetimeModel.removeAllElements();
		for (Integer value : values) {
			lifetimeModel.addElement(value);
		}

	}

}
