package grith.jgrith.view.swing;

import grith.jgrith.utils.CredentialHelpers;
import grith.jgrith.voms.VO;
import grith.jgrith.voms.VOManagement.VOManagement;
import grith.jgrith.vomsProxy.VomsException;
import grith.jgrith.vomsProxy.VomsProxy;

import java.awt.BorderLayout;
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
import javax.swing.JTabbedPane;
import javax.swing.SwingConstants;
import javax.swing.border.TitledBorder;

import org.globus.gsi.GlobusCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class X509AndShibVomsProxyInitPanel extends JPanel implements
ProxyInitListener {

	private JLabel passwordLabel;
	private JLabel usernameLabel;
	private JLabel idpLabel;
	private JPanel shibbolethPanel;
	private JTabbedPane tabbedPane_1;
	private JPanel panel;
	static final Logger myLogger = LoggerFactory
			.getLogger(X509AndShibVomsProxyInitPanel.class);

	public static final String NON_VOMS_PROXY_NAME = "None";

	private static final String SHIBBOLETH_TAB_NAME = "Institution login";
	private static final String X509_AUTH_TAB_NAME = "Certificate login";

	private JButton voButton;
	private JButton initButton;
	private JComboBox voComboBox;
	private JComboBox lifetimeComboBox;
	private JLabel label_2;
	private JLabel label_1;

	public static final Integer[] DEFAULT_LIFETIMES = new Integer[] { 1, 2, 3,
		7, 14, 21 };
	public static final String DEFAULT_TITLE = "Authentication";

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
	public X509AndShibVomsProxyInitPanel() {
		super();
		setBorder(DEFAULT_TITLE);
		setLayout(new FormLayout(new ColumnSpec[] {
				FormFactory.RELATED_GAP_COLSPEC, ColumnSpec.decode("65dlu"),
				FormFactory.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("25dlu:grow(1.0)"),
				FormFactory.RELATED_GAP_COLSPEC, FormFactory.DEFAULT_COLSPEC,
				FormFactory.RELATED_GAP_COLSPEC }, new RowSpec[] {
				FormFactory.RELATED_GAP_ROWSPEC, RowSpec.decode("67dlu"),
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC }));
		add(getLabel_1(), new CellConstraints(2, 4));
		add(getLabel_2(), new CellConstraints(2, 6));
		add(getLifetimeComboBox(), new CellConstraints(4, 4));
		add(getVoComboBox(), new CellConstraints(4, 6));
		add(getInitButton(), new CellConstraints(6, 4));
		add(getVoButton(), new CellConstraints(6, 6));
		add(getPanel(), new CellConstraints(2, 2, 5, 1, CellConstraints.FILL,
				CellConstraints.FILL));
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
	protected JLabel getIdpLabel() {
		if (idpLabel == null) {
			idpLabel = new JLabel();
			idpLabel.setHorizontalAlignment(SwingConstants.TRAILING);
			idpLabel.setText("IDP:");
		}
		return idpLabel;
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
								X509AndShibVomsProxyInitPanel.this.setCursor(Cursor
										.getPredefinedCursor(Cursor.WAIT_CURSOR));
								getInitButton().setEnabled(false);
								getVoButton().setEnabled(false);
								initProxy();
							} catch (Exception e) {
								X509AndShibVomsProxyInitPanel.this.setCursor(Cursor
										.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
								myLogger.error("Proxy init error: "
										+ e.getLocalizedMessage());
								JOptionPane.showMessageDialog(
										X509AndShibVomsProxyInitPanel.this,
										e.getLocalizedMessage(),
										"Proxy init error",
										JOptionPane.ERROR_MESSAGE);
								return;
							} finally {
								X509AndShibVomsProxyInitPanel.this.setCursor(Cursor
										.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
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
	protected JPanel getPanel() {
		if (panel == null) {
			panel = new JPanel();
			panel.setLayout(new BorderLayout());
			panel.add(getTabbedPane_1());
		}
		return panel;
	}

	/**
	 * @return
	 */
	protected JLabel getPasswordLabel() {
		if (passwordLabel == null) {
			passwordLabel = new JLabel();
			passwordLabel.setHorizontalAlignment(SwingConstants.TRAILING);
			passwordLabel.setText("Password:");
		}
		return passwordLabel;
	}

	/**
	 * @return
	 */
	protected JPanel getShibbolethPanel() {
		if (shibbolethPanel == null) {
			shibbolethPanel = new JPanel();
			shibbolethPanel.setLayout(new FormLayout(new ColumnSpec[] {
					FormFactory.DEFAULT_COLSPEC,
					FormFactory.RELATED_GAP_COLSPEC,
					FormFactory.DEFAULT_COLSPEC },
					new RowSpec[] { FormFactory.DEFAULT_ROWSPEC,
					FormFactory.RELATED_GAP_ROWSPEC,
					FormFactory.DEFAULT_ROWSPEC,
					FormFactory.RELATED_GAP_ROWSPEC,
					RowSpec.decode("default") }));
			shibbolethPanel.add(getIdpLabel(), new CellConstraints());
			shibbolethPanel.add(getUsernameLabel(), new CellConstraints(1, 3));
			shibbolethPanel.add(getPasswordLabel(), new CellConstraints(1, 5));
		}
		return shibbolethPanel;
	}

	/**
	 * @return
	 */
	protected JTabbedPane getTabbedPane_1() {
		if (tabbedPane_1 == null) {
			tabbedPane_1 = new JTabbedPane();
			tabbedPane_1.addTab(SHIBBOLETH_TAB_NAME, null,
					getShibbolethPanel(), null);
		}
		return tabbedPane_1;
	}

	/**
	 * @return
	 */
	protected JLabel getUsernameLabel() {
		if (usernameLabel == null) {
			usernameLabel = new JLabel();
			usernameLabel.setHorizontalAlignment(SwingConstants.TRAILING);
			usernameLabel.setText("Username:");
		}
		return usernameLabel;
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
								X509AndShibVomsProxyInitPanel.this.setCursor(Cursor
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
								X509AndShibVomsProxyInitPanel.this.setCursor(Cursor
										.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
								JOptionPane.showMessageDialog(
										X509AndShibVomsProxyInitPanel.this,
										e.getLocalizedMessage(), "Voms error",
										JOptionPane.ERROR_MESSAGE);
								return;
							} finally {
								X509AndShibVomsProxyInitPanel.this.setCursor(Cursor
										.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
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
		int lifetime_in_hours = ((Integer) getLifetimeComboBox()
				.getSelectedItem()) * 24;

		if (SHIBBOLETH_TAB_NAME.equals(getTabbedPane_1().getTitleAt(
				getTabbedPane_1().getSelectedIndex()))) {

		} else if (X509_AUTH_TAB_NAME.equals(getTabbedPane_1().getTitleAt(
				getTabbedPane_1().getSelectedIndex()))) {
			try {
			} catch (Exception e) {
				throw e;
			}
			fireNewProxyCreated(credential);
		}

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
