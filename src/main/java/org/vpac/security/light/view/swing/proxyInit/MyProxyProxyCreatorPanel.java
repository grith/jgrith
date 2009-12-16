package org.vpac.security.light.view.swing.proxyInit;

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
import javax.swing.JTextField;

import org.apache.log4j.Logger;
import org.globus.gsi.GlobusCredential;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;
import org.vpac.security.light.CredentialHelpers;
import org.vpac.security.light.control.UserProperty;
import org.vpac.security.light.myProxy.MyProxy_light;

import au.org.arcs.commonInterfaces.ProxyCreatorHolder;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class MyProxyProxyCreatorPanel extends JPanel {

	private JLabel lifetimeinDaysLabel;
	private JComboBox comboBox;
	private static final Logger myLogger = Logger
			.getLogger(MyProxyProxyCreatorPanel.class.getName());

	public static final MyProxy DEFAULT_MYPROXY = new MyProxy(
			"myproxy.arcs.org.au", 443);
	public static final Integer[] DEFAULT_PROXY_LIFETIME_VALUES = new Integer[] {
			1, 2, 3, 7, 14, 21 };

	private MyProxy myproxy = null;

	private JButton button;
	private JLabel titleLabel;
	private JPasswordField passwordField;
	private JTextField usernameTextField;
	private JLabel passwordLabel;
	private JLabel usernameLabel;

	private ProxyCreatorHolder holder = null;
	private DefaultComboBoxModel lifetimeModel = new DefaultComboBoxModel(
			DEFAULT_PROXY_LIFETIME_VALUES);

	/**
	 * Create the panel
	 */
	public MyProxyProxyCreatorPanel() {
		super();
		setLayout(new FormLayout(new ColumnSpec[] {
				FormFactory.RELATED_GAP_COLSPEC, FormFactory.DEFAULT_COLSPEC,
				FormFactory.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("42dlu:grow"),
				FormFactory.RELATED_GAP_COLSPEC, ColumnSpec.decode("17dlu"),
				FormFactory.RELATED_GAP_COLSPEC, ColumnSpec.decode("39dlu"),
				FormFactory.RELATED_GAP_COLSPEC, }, new RowSpec[] {
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.PARAGRAPH_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.PARAGRAPH_GAP_ROWSPEC,
				RowSpec.decode("default:grow"),
				FormFactory.RELATED_GAP_ROWSPEC, }));
		add(getUsernameLabel(), new CellConstraints(2, 4));
		add(getPasswordLabel(), new CellConstraints(2, 6));
		add(getUsernameTextField(), new CellConstraints(4, 4, 5, 1));
		add(getPasswordField(), new CellConstraints(4, 6, 5, 1));
		add(getTitleLabel(), new CellConstraints(2, 2, 7, 1));
		add(getButton(), "6, 10, 3, 1, default, bottom");
		add(getComboBox(), new CellConstraints(8, 8));
		add(getLifetimeinDaysLabel(), new CellConstraints(2, 8, 3, 1));

		//

		enablePanel(false);
	}

	private void enablePanel(boolean enable) {

		getButton().setEnabled(enable);
		getUsernameTextField().setEnabled(enable);
		getPasswordField().setEnabled(enable);
		getComboBox().setEnabled(enable);

	}

	/**
	 * @return
	 */
	protected JButton getButton() {
		if (button == null) {
			button = new JButton();
			button.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					if (holder != null) {

						new Thread() {
							public void run() {
								myProxyLogin();
							}
						}.start();

					}

				}
			});
			button.setText("Authenticate");
		}
		return button;
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
	protected JLabel getLifetimeinDaysLabel() {
		if (lifetimeinDaysLabel == null) {
			lifetimeinDaysLabel = new JLabel();
			lifetimeinDaysLabel.setText("Lifetime (in days):");
		}
		return lifetimeinDaysLabel;
	}

	public MyProxy getMyproxy() {

		if (myproxy == null) {
			return DEFAULT_MYPROXY;
		}

		return myproxy;
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
									myProxyLogin();
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
	protected JLabel getPasswordLabel() {
		if (passwordLabel == null) {
			passwordLabel = new JLabel();
			passwordLabel.setText("Password:");
		}
		return passwordLabel;
	}

	/**
	 * @return
	 */
	protected JLabel getTitleLabel() {
		if (titleLabel == null) {
			titleLabel = new JLabel();
			titleLabel.setText("Please provide your MyProxy details:");
		}
		return titleLabel;
	}

	/**
	 * @return
	 */
	protected JLabel getUsernameLabel() {
		if (usernameLabel == null) {
			usernameLabel = new JLabel();
			usernameLabel.setText("Username:");
		}
		return usernameLabel;
	}

	/**
	 * @return
	 */
	protected JTextField getUsernameTextField() {
		if (usernameTextField == null) {
			usernameTextField = new JTextField();
			usernameTextField.addKeyListener(new KeyAdapter() {
				public void keyPressed(final KeyEvent e) {
					if (e.getKeyCode() == KeyEvent.VK_ENTER) {
						getPasswordField().requestFocus();
					}
				}
			});
		}
		return usernameTextField;
	}

	private void myProxyLogin() {

		setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
		enablePanel(false);

		String username = getUsernameTextField().getText();

		if (username == null || "".equals(username)) {
			setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
			JOptionPane.showMessageDialog(MyProxyProxyCreatorPanel.this,
					"You have to provide a username", "No username",
					JOptionPane.ERROR_MESSAGE);
			enablePanel(true);
			return;
		}

		try {
			UserProperty.setProperty(UserProperty.LAST_MYPROXY_USERNAME_KEY,
					username);
		} catch (Exception e2) {
			// doesn't really matter
		}

		char[] passphrase = getPasswordField().getPassword();

		if (passphrase == null || passphrase.length == 0) {
			setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
			JOptionPane.showMessageDialog(MyProxyProxyCreatorPanel.this,
					"You have to provide a password", "No password",
					JOptionPane.ERROR_MESSAGE);
			enablePanel(true);
			return;
		}

		Integer lifetimeInDays = null;

		try {
			lifetimeInDays = (Integer) lifetimeModel.getSelectedItem();
		} catch (Exception e) {
			setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
			JOptionPane.showMessageDialog(MyProxyProxyCreatorPanel.this,
					"You have to specify an integer value for the lifetime",
					"Error parsing lifetime value", JOptionPane.ERROR_MESSAGE);
			enablePanel(true);
			return;
		}

		int lifetimeInSecs = lifetimeInDays * 24 * 3600;

		try {
			GSSCredential cred = MyProxy_light.getDelegation(getMyproxy()
					.getHost(), getMyproxy().getPort(), username, passphrase,
					lifetimeInSecs);
			GlobusCredential proxy = CredentialHelpers
					.unwrapGlobusCredential(cred);
			holder.proxyCreated(proxy);
			getPasswordField().setText("");
			enablePanel(true);
			setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
		} catch (MyProxyException e1) {
			setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
			JOptionPane.showMessageDialog(MyProxyProxyCreatorPanel.this,
					"Could not download proxy:\n\n" + e1.getLocalizedMessage(),
					"Proxy download error", JOptionPane.ERROR_MESSAGE);
			enablePanel(true);
			return;
		}

	}

	public void setMyproxy(MyProxy myproxy) {
		this.myproxy = myproxy;
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
