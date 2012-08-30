package grith.jgrith.view.swing;

import grith.jgrith.Environment;
import grith.jgrith.control.UserProperty;
import grith.jgrith.myProxy.MyProxy_light;
import grith.jgrith.utils.CredentialHelpers;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.border.TitledBorder;

import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GlobusCredentialException;
import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class MyProxyUpAndDownloadPanel extends JPanel implements
ProxyInitListener {

	private JPasswordField passwordField;
	private JTextField textField;
	private JLabel label_1;
	private JLabel label;
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
	public MyProxyUpAndDownloadPanel() {
		super();
		setBorder(new TitledBorder(null, "MyProxy",
				TitledBorder.DEFAULT_JUSTIFICATION,
				TitledBorder.DEFAULT_POSITION, null, null));
		setLayout(new FormLayout(new ColumnSpec[] {
				FormFactory.RELATED_GAP_COLSPEC, ColumnSpec.decode("65dlu"),
				FormFactory.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("default:grow(1.0)"),
				FormFactory.RELATED_GAP_COLSPEC }, new RowSpec[] {
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				RowSpec.decode("top:11dlu"), FormFactory.DEFAULT_ROWSPEC,
				RowSpec.decode("top:9dlu") }));
		add(getDownloadButton(), new CellConstraints(2, 6,
				CellConstraints.LEFT, CellConstraints.DEFAULT));
		add(getUploadButton(), new CellConstraints(4, 6, CellConstraints.RIGHT,
				CellConstraints.DEFAULT));
		add(getLabel(), new CellConstraints(2, 2, CellConstraints.RIGHT,
				CellConstraints.DEFAULT));
		add(getLabel_1(), new CellConstraints(2, 4, CellConstraints.RIGHT,
				CellConstraints.DEFAULT));
		add(getTextField(), new CellConstraints(4, 2));
		add(getPasswordField(), new CellConstraints(4, 4));
		//

		String defaultUsername = UserProperty
				.getProperty(UserProperty.LAST_MYPROXY_USERNAME_KEY);
		if ((defaultUsername == null) || "".equals(defaultUsername)) {
			defaultUsername = System.getProperty("user.name");
		}
		getTextField().setText(defaultUsername);
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

					String username = getTextField().getText();

					if ((username == null) || "".equals(username)) {
						JOptionPane.showMessageDialog(
								MyProxyUpAndDownloadPanel.this,
								"You have to provide a username",
								"No username", JOptionPane.ERROR_MESSAGE);
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
								MyProxyUpAndDownloadPanel.this,
								"You have to provide a password",
								"No password", JOptionPane.ERROR_MESSAGE);
						return;
					}

					try {
						GSSCredential cred = MyProxy_light.getDelegation(
								getMyproxy().getHost(), getMyproxy().getPort(),
								username, passphrase, -1);
						currentCredential = CredentialHelpers
								.unwrapGlobusCredential(cred);
						getPasswordField().setText("");
						fireNewProxyCreated(currentCredential);
					} catch (MyProxyException e1) {
						JOptionPane.showMessageDialog(
								MyProxyUpAndDownloadPanel.this,
								"Could not download proxy:\n\n"
										+ e1.getLocalizedMessage(),
										"Proxy download error",
										JOptionPane.ERROR_MESSAGE);
						return;
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

	public MyProxy getMyproxy() {

		if (myproxy == null) {
			return Environment.getDefaultMyProxy();
		}

		return myproxy;
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
				@Override
				public void actionPerformed(final ActionEvent e) {

					String username = getTextField().getText();

					if ((username == null) || "".equals(username)) {
						JOptionPane.showMessageDialog(
								MyProxyUpAndDownloadPanel.this,
								"You have to provide a username",
								"No username", JOptionPane.ERROR_MESSAGE);
						return;
					}

					InitParams params = null;
					try {
						params = MyProxy_light.prepareProxyParameters(username,
								null, "*", "*", null, -1);
					} catch (MyProxyException e3) {
						JOptionPane
						.showMessageDialog(
								MyProxyUpAndDownloadPanel.this,
								"Error preparing myproxy parameters: "
										+ e3.getLocalizedMessage()
										+ "\n\n. Please contact your administrator.",
										"MyProxy error",
										JOptionPane.ERROR_MESSAGE);
					}

					params.setUserName(username);

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
								MyProxyUpAndDownloadPanel.this,
								"You have to provide a password",
								"No password", JOptionPane.ERROR_MESSAGE);
						return;
					}

					params.setLifetime((int) currentCredential.getTimeLeft());
					try {
						MyProxy_light.init(getMyproxy(), CredentialHelpers.wrapGlobusCredential(currentCredential),
								params, passphrase);
						getPasswordField().setText("");
					} catch (Exception e1) {
						JOptionPane.showMessageDialog(
								MyProxyUpAndDownloadPanel.this,
								"Could not upload proxy: "
										+ e1.getLocalizedMessage(),
										"Upload error", JOptionPane.ERROR_MESSAGE);
						return;
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
