package org.vpac.security.light.view.swing;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;
import org.vpac.security.light.control.UserProperty;
import org.vpac.security.light.myProxy.MyProxy_light;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class MyProxyDownloadDialog extends JDialog {

	/**
	 * Launch the application
	 * 
	 * @param args
	 */
	public static void main(String args[]) {
		try {
			MyProxyDownloadDialog dialog = new MyProxyDownloadDialog();
			dialog.addWindowListener(new WindowAdapter() {
				@Override
				public void windowClosing(WindowEvent e) {
					System.exit(0);
				}
			});
			dialog.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private JButton cancelButton;
	private JButton downloadButton;
	private JPasswordField passwordField;
	private JTextField textField;
	private JLabel label_1;
	private JLabel label;

	private JPanel panel;
	private MyProxy myproxy = null;

	private GSSCredential cred = null;

	/**
	 * Create the dialog
	 */
	public MyProxyDownloadDialog() {
		super();
		setModal(true);
		setTitle("Download a proxy");
		setBounds(100, 100, 500, 168);
		getContentPane().add(getPanel(), BorderLayout.CENTER);
		//
	}

	public MyProxyDownloadDialog(MyProxy myproxy) {
		this();
		initialize(myproxy);
	}

	/**
	 * @return
	 */
	protected JButton getCancelButton() {
		if (cancelButton == null) {
			cancelButton = new JButton();
			cancelButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {
					cred = null;
					dispose();
				}
			});
			cancelButton.setText("Cancel");
		}
		return cancelButton;
	}

	/**
	 * @return
	 */

	public GSSCredential getCred() {
		return cred;
	}

	/**
	 * @return
	 */
	protected JButton getDownloadButton() {
		if (downloadButton == null) {
			downloadButton = new JButton();
			downloadButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {
					String username = getTextField().getText();

					if ((username == null) || "".equals(username)) {
						JOptionPane.showMessageDialog(
								MyProxyDownloadDialog.this,
								"You have to provide a username",
								"No username", JOptionPane.ERROR_MESSAGE);
						cred = null;
						return;
					}

					try {
						UserProperty.setProperty(
								UserProperty.LAST_MYPROXY_USERNAME_KEY,
								username);
					} catch (Exception e2) {
						// doesn't really matter
					}

					char[] passphrase = getPasswordField().getPassword();

					if ((passphrase == null) || (passphrase.length == 0)) {
						JOptionPane.showMessageDialog(
								MyProxyDownloadDialog.this,
								"You have to provide a password",
								"No password", JOptionPane.ERROR_MESSAGE);
						cred = null;
						return;
					}

					try {
						cred = MyProxy_light.getDelegation(myproxy.getHost(),
								myproxy.getPort(), username, passphrase, -1);
					} catch (MyProxyException e1) {
						cred = null;
						JOptionPane.showMessageDialog(
								MyProxyDownloadDialog.this,
								"Could not download proxy:\n\n"
										+ e1.getLocalizedMessage(),
								"Proxy download error",
								JOptionPane.ERROR_MESSAGE);
						return;
					}

					dispose();
				}
			});
			downloadButton.setText("Download");
		}
		return downloadButton;
	}

	/**
	 * @return
	 */
	protected JLabel getLabel() {
		if (label == null) {
			label = new JLabel();
			label.setText("Username:");
		}
		return label;
	}

	/**
	 * @return
	 */
	protected JLabel getLabel_1() {
		if (label_1 == null) {
			label_1 = new JLabel();
			label_1.setText("Password:");
		}
		return label_1;
	}

	/**
	 * @return
	 */
	protected JPanel getPanel() {
		if (panel == null) {
			panel = new JPanel();
			panel.setLayout(new FormLayout(
					new ColumnSpec[] { new ColumnSpec("left:16dlu"),
							FormFactory.DEFAULT_COLSPEC,
							FormFactory.RELATED_GAP_COLSPEC,
							new ColumnSpec("default:grow(1.0)"),
							FormFactory.RELATED_GAP_COLSPEC,
							FormFactory.DEFAULT_COLSPEC,
							new ColumnSpec("left:18dlu") }, new RowSpec[] {
							new RowSpec("top:15dlu"),
							FormFactory.DEFAULT_ROWSPEC,
							new RowSpec("top:9dlu"),
							FormFactory.DEFAULT_ROWSPEC,
							new RowSpec("top:11dlu"),
							FormFactory.DEFAULT_ROWSPEC }));
			panel.add(getLabel(), new CellConstraints(2, 2,
					CellConstraints.RIGHT, CellConstraints.DEFAULT));
			panel.add(getLabel_1(), new CellConstraints(2, 4,
					CellConstraints.RIGHT, CellConstraints.DEFAULT));
			panel.add(getTextField(), new CellConstraints(4, 2, 3, 1));
			panel.add(getPasswordField(), new CellConstraints(4, 4, 3, 1));
			panel.add(getDownloadButton(), new CellConstraints(6, 6,
					CellConstraints.RIGHT, CellConstraints.DEFAULT));
			panel.add(getCancelButton(), new CellConstraints(4, 6,
					CellConstraints.RIGHT, CellConstraints.DEFAULT));
		}
		return panel;
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
	protected JTextField getTextField() {
		if (textField == null) {
			textField = new JTextField();
		}
		return textField;
	}

	public void initialize(MyProxy myproxy) {
		this.myproxy = myproxy;

		String defaultUsername = UserProperty
				.getProperty(UserProperty.LAST_MYPROXY_USERNAME_KEY);
		if ((defaultUsername == null) || "".equals(defaultUsername)) {
			defaultUsername = System.getProperty("user.name");
		}

		getTextField().setText(defaultUsername);

	}

}
