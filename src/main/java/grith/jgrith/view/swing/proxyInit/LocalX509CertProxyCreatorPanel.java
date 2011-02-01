package grith.jgrith.view.swing.proxyInit;

import grisu.jcommons.commonInterfaces.ProxyCreatorHolder;
import grith.jgrith.CredentialHelpers;
import grith.jgrith.plainProxy.PlainProxy;
import grith.jgrith.view.swing.Utils;

import java.awt.Cursor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import org.globus.gsi.GlobusCredential;
import org.ietf.jgss.GSSCredential;


import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class LocalX509CertProxyCreatorPanel extends JPanel {

	public static final Integer[] DEFAULT_PROXY_LIFETIME_VALUES = new Integer[] {
			1, 2, 3, 7, 14, 21 };

	private JComboBox comboBox;
	private JLabel lifetimeInDaysLabel;
	private JButton authenticateButton;
	private JPasswordField passwordField;
	private JLabel pleaseProvideYourLabel;
	private ProxyCreatorHolder holder = null;

	private DefaultComboBoxModel lifetimeModel = new DefaultComboBoxModel(
			DEFAULT_PROXY_LIFETIME_VALUES);

	/**
	 * Create the panel
	 */
	public LocalX509CertProxyCreatorPanel() {
		super();
		setLayout(new FormLayout(new ColumnSpec[] {
				FormFactory.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("43dlu:grow"),
				FormFactory.RELATED_GAP_COLSPEC, FormFactory.DEFAULT_COLSPEC,
				FormFactory.RELATED_GAP_COLSPEC, }, new RowSpec[] {
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				RowSpec.decode("10dlu"), FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				RowSpec.decode("11dlu"), RowSpec.decode("default:grow"),
				FormFactory.RELATED_GAP_ROWSPEC, }));
		//
		enablePanel(false);
		add(getPleaseProvideYourLabel(), new CellConstraints(2, 2, 3, 1));
		add(getPasswordField(), new CellConstraints(2, 4, 3, 1));
		add(getAuthenticateButton(), "4, 8, default, bottom");
		add(getLifetimeInDaysLabel(), new CellConstraints(2, 6));
		add(getComboBox(), new CellConstraints(4, 6));
	}

	public void enablePanel(boolean enable) {
		getPasswordField().setEnabled(enable);
		getAuthenticateButton().setEnabled(enable);
		getComboBox().setEnabled(enable);
	}

	/**
	 * @return
	 */
	protected JButton getAuthenticateButton() {
		if (authenticateButton == null) {
			authenticateButton = new JButton();
			authenticateButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					if (holder != null) {
						new Thread() {
							public void run() {
								gridProxyInit();
							}
						}.start();
					}

				}
			});
			authenticateButton.setText("Authenticate");
		}
		return authenticateButton;
	}

	/**
	 * @return
	 */
	protected JComboBox getComboBox() {
		if (comboBox == null) {
			comboBox = new JComboBox(lifetimeModel);
			comboBox.setEditable(true);
		}
		return comboBox;
	}

	/**
	 * @return
	 */
	protected JLabel getLifetimeInDaysLabel() {
		if (lifetimeInDaysLabel == null) {
			lifetimeInDaysLabel = new JLabel();
			lifetimeInDaysLabel.setText("Lifetime in days:");
		}
		return lifetimeInDaysLabel;
	}

	/**
	 * @return
	 */
	protected JPasswordField getPasswordField() {
		if (passwordField == null) {
			passwordField = new JPasswordField();
			passwordField.addKeyListener(new KeyAdapter() {
				public void keyPressed(final KeyEvent e) {
					if (e.getKeyCode() == KeyEvent.VK_ENTER) {
						if (holder != null) {
							new Thread() {
								public void run() {
									gridProxyInit();
								}
							}.start();
						}
					}
				}
			});
		}
		return passwordField;
	}

	/**
	 * @return
	 */
	protected JLabel getPleaseProvideYourLabel() {
		if (pleaseProvideYourLabel == null) {
			pleaseProvideYourLabel = new JLabel();
			pleaseProvideYourLabel
					.setText("Please provide your private key passphrase:");
		}
		return pleaseProvideYourLabel;
	}

	private void gridProxyInit() {

		setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
		enablePanel(false);

		Integer lifetimeInDays = null;

		try {
			lifetimeInDays = (Integer) lifetimeModel.getSelectedItem();
		} catch (Exception e) {
			setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
			JOptionPane.showMessageDialog(LocalX509CertProxyCreatorPanel.this,
					"You have to specify an integer value for the lifetime",
					"Error parsing lifetime value", JOptionPane.ERROR_MESSAGE);
			enablePanel(true);
			return;
		}

		int lifetime_in_hours = lifetimeInDays * 24;

		try {

			GSSCredential cred = PlainProxy.init(getPasswordField()
					.getPassword(), lifetime_in_hours);
			GlobusCredential proxy = CredentialHelpers
					.unwrapGlobusCredential(cred);
			holder.proxyCreated(proxy);
			getPasswordField().setText("");
			setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
			enablePanel(true);
		} catch (Exception e1) {
			setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
			enablePanel(true);
			Utils.showErrorMessage(LocalX509CertProxyCreatorPanel.this,
					"localProxyCreationError", e1);
		}

	}

	public void setProxyCreatorHolder(ProxyCreatorHolder holder) {
		this.holder = holder;
		if (this.holder == null) {
			enablePanel(false);
		} else {
			enablePanel(true);
		}
	}

}
