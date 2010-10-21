package org.vpac.security.light.view.swing;

import java.awt.BorderLayout;
import java.awt.Cursor;
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

import org.globus.gsi.GlobusCredential;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.vpac.security.light.control.UserProperty;
import org.vpac.security.light.myProxy.MyProxy_light;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class MyProxyUploadDialog extends JDialog {

	/**
	 * Launch the application
	 * 
	 * @param args
	 */
	public static void main(String args[]) {
		try {
			MyProxyUploadDialog dialog = new MyProxyUploadDialog();
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
	private JButton uploadButton;
	private JPasswordField passwordField;
	private JTextField textField;
	private JLabel label_1;
	private JLabel label;

	private JPanel panel;
	private GlobusCredential proxy = null;
	private MyProxy myproxy = null;

	private InitParams params = null;
	private Exception uploadException = null;

	private boolean success = false;

	/**
	 * Create the dialog
	 */
	public MyProxyUploadDialog() {
		super();
		setModal(true);
		setTitle("Upload a proxy");
		setBounds(100, 100, 500, 162);
		getContentPane().add(getPanel(), BorderLayout.CENTER);
		//
	}

	public MyProxyUploadDialog(GlobusCredential credential, InitParams params,
			MyProxy myproxy) {
		this();
		initialize(credential, params, myproxy);
	}

	private void enablePanel(boolean enable) {
		getUploadButton().setEnabled(enable);
		getCancelButton().setEnabled(enable);
		getTextField().setEnabled(enable);
		getPasswordField().setEnabled(enable);
	}

	/**
	 * @return
	 */
	protected JButton getCancelButton() {
		if (cancelButton == null) {
			cancelButton = new JButton();
			cancelButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {
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
							new ColumnSpec("left:15dlu") }, new RowSpec[] {
							new RowSpec("top:15dlu"),
							FormFactory.DEFAULT_ROWSPEC,
							new RowSpec("top:10dlu"),
							FormFactory.DEFAULT_ROWSPEC,
							new RowSpec("top:11dlu"),
							FormFactory.DEFAULT_ROWSPEC }));
			panel.add(getLabel(), new CellConstraints(2, 2,
					CellConstraints.RIGHT, CellConstraints.DEFAULT));
			panel.add(getLabel_1(), new CellConstraints(2, 4,
					CellConstraints.RIGHT, CellConstraints.DEFAULT));
			panel.add(getTextField(), new CellConstraints(4, 2, 3, 1));
			panel.add(getPasswordField(), new CellConstraints(4, 4, 3, 1));
			panel.add(getUploadButton(), new CellConstraints(6, 6,
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

	/**
	 * @return
	 */
	protected JButton getUploadButton() {
		if (uploadButton == null) {
			uploadButton = new JButton();
			uploadButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {

					new Thread() {
						@Override
						public void run() {
							enablePanel(false);
							setCursor(Cursor
									.getPredefinedCursor(Cursor.WAIT_CURSOR));
							String username = getTextField().getText();

							if ((username == null) || "".equals(username)) {
								setCursor(Cursor
										.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
								JOptionPane.showMessageDialog(
										MyProxyUploadDialog.this,
										"You have to provide a username",
										"No username",
										JOptionPane.ERROR_MESSAGE);
								enablePanel(true);
								return;
							}

							params.setUserName(username);

							try {
								UserProperty.setProperty(
										UserProperty.LAST_MYPROXY_USERNAME_KEY,
										username);
							} catch (Exception e2) {
								// doesn't really matter
							}

							char[] passphrase = getPasswordField()
									.getPassword();

							if ((passphrase == null)
									|| (passphrase.length == 0)) {
								setCursor(Cursor
										.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
								JOptionPane.showMessageDialog(
										MyProxyUploadDialog.this,
										"You have to provide a password",
										"No password",
										JOptionPane.ERROR_MESSAGE);
								enablePanel(true);
								return;
							}

							params.setLifetime((int) proxy.getTimeLeft());
							try {
								MyProxy_light.init(myproxy, proxy, params,
										passphrase);
							} catch (Exception e1) {
								setCursor(Cursor
										.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
								JOptionPane.showMessageDialog(
										MyProxyUploadDialog.this,
										"Could not upload proxy: "
												+ e1.getLocalizedMessage(),
										"Upload error",
										JOptionPane.ERROR_MESSAGE);
								uploadException = e1;
								enablePanel(true);
								return;
							}
							success = true;
							setCursor(Cursor
									.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
							getPasswordField().setText("");
							enablePanel(true);
							setVisible(false);

						}
					}.start();
				}
			});
			uploadButton.setText("Upload");
		}
		return uploadButton;
	}

	/**
	 * @return
	 */

	public Exception getUploadException() {
		return uploadException;
	}

	public void initialize(GlobusCredential credential, InitParams params,
			MyProxy myproxy) {
		this.proxy = credential;
		this.myproxy = myproxy;
		this.params = params;

		String defaultUsername = UserProperty
				.getProperty(UserProperty.LAST_MYPROXY_USERNAME_KEY);
		if ((defaultUsername == null) || "".equals(defaultUsername)) {
			defaultUsername = params.getUserName();
			if ((defaultUsername == null) || "".equals(defaultUsername)) {
				defaultUsername = System.getProperty("user.name");
			}
		}

		getTextField().setText(defaultUsername);
	}

	public boolean isSuccess() {
		return success;
	}

}
