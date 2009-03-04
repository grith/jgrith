package org.vpac.security.light.view.swing;

import java.awt.Cursor;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.net.URL;
import java.net.URLClassLoader;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import org.globus.myproxy.InitParams;
import org.globus.myproxy.MyProxy;
import org.ietf.jgss.GSSCredential;
import org.vpac.security.light.Init;
import org.vpac.security.light.certificate.CertificateHelper;
import org.vpac.security.light.myProxy.MyProxy_light;
import org.vpac.security.light.plainProxy.PlainProxy;
import org.vpac.security.light.utils.ActionPerformedListener;

public class MyProxyInitPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JLabel jLabel = null;
	private JLabel jLabel1 = null;
	private JLabel jLabel2 = null;
	private JTextField usernameTextField = null;
	private JPasswordField passwordField = null;
	private JLabel jLabel3 = null;
	private JComboBox lifetimeComboBox = null;
	private JButton initButton = null;

	ActionPerformedListener listener = null;
	public static final String SUCCESS_ACTION_NAME = "Proxy created";

	private String defaultLifeTimes = "1,2,3,12,28,24,48,96";
	private String myproxyServer = null;
	private int myproxyPort = -1;
	private int lifetime_in_seconds = -1;

	private String allowed_retrievers = null;
	private String allowed_renewers = null;
	private JLabel jLabel4 = null;
	private JPasswordField privateKeyPassphraseField = null;

	/**
	 * Creates a panel to enable the user to "upload" a proxy.
	 * 
	 * @param listener
	 *            the listener that gets notified when something has happened
	 * @param myproxyServer
	 *            the myproxy server to contact
	 * @param myproxyPort
	 *            the port of the myproxy server
	 * @param lifetime_in_seconds
	 *            the lifetime of the proxy in seconds. If you specify a value <=
	 *            0 a combobox is rendered for the user.
	 * @param allowed_retrievers
	 *            the allowed retrievers
	 * @param allowed_renewers
	 *            the allowed renewers
	 */
	public MyProxyInitPanel(ActionPerformedListener listener,
			String myproxyServer, int myproxyPort, int lifetime_in_seconds,
			String allowed_retrievers, String allowed_renewers) {
		super();
		

//		     StringBuffer classpath = new StringBuffer();
//		     ClassLoader applicationClassLoader = this.getClass().getClassLoader();
//		     if (applicationClassLoader == null) {
//		         applicationClassLoader = ClassLoader.getSystemClassLoader();
//		     }
//		     URL[] urls = ((URLClassLoader)applicationClassLoader).getURLs();
//		      for(int i=0; i < urls.length; i++) {
//		          classpath.append(urls[i].getFile()).append("\r\n");
//		      }    
//		     
//		      System.out.println("Classpath: "+classpath.toString());
		
		Init.initBouncyCastle();
		if (!CertificateHelper.globusCredentialsReady())
			throw new RuntimeException(
					"No certificate & private key available to create a proxy.");
		this.listener = listener;
		this.myproxyServer = myproxyServer;
		this.myproxyPort = myproxyPort;
		this.lifetime_in_seconds = lifetime_in_seconds;
		this.allowed_retrievers = allowed_retrievers;
		this.allowed_renewers = allowed_renewers;
		initialize();
	}

	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
		GridBagConstraints gridBagConstraints31 = new GridBagConstraints();
		gridBagConstraints31.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints31.gridy = 1;
		gridBagConstraints31.weightx = 1.0;
		gridBagConstraints31.insets = new Insets(20, 15, 10, 15);
		gridBagConstraints31.gridx = 1;
		GridBagConstraints gridBagConstraints21 = new GridBagConstraints();
		gridBagConstraints21.gridx = 0;
		gridBagConstraints21.insets = new Insets(20, 15, 10, 0);
		gridBagConstraints21.anchor = GridBagConstraints.EAST;
		gridBagConstraints21.gridy = 1;
		jLabel4 = new JLabel();
		jLabel4.setText("Private key passphrase:");
		GridBagConstraints gridBagConstraints11 = new GridBagConstraints();
		gridBagConstraints11.gridx = 1;
		gridBagConstraints11.anchor = GridBagConstraints.EAST;
		gridBagConstraints11.insets = new Insets(20, 0, 15, 15);
		gridBagConstraints11.gridy = 5;
		GridBagConstraints gridBagConstraints6 = new GridBagConstraints();
		gridBagConstraints6.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints6.gridy = 4;
		gridBagConstraints6.weightx = 1.0;
		gridBagConstraints6.insets = new Insets(10, 15, 0, 15);
		gridBagConstraints6.gridx = 1;
		GridBagConstraints gridBagConstraints5 = new GridBagConstraints();
		gridBagConstraints5.gridx = 0;
		gridBagConstraints5.insets = new Insets(10, 15, 0, 0);
		gridBagConstraints5.anchor = GridBagConstraints.EAST;
		gridBagConstraints5.gridy = 4;
		jLabel3 = new JLabel();
		jLabel3.setText("Proxy lifetime (days):");
		GridBagConstraints gridBagConstraints4 = new GridBagConstraints();
		gridBagConstraints4.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints4.gridy = 3;
		gridBagConstraints4.weightx = 1.0;
		gridBagConstraints4.insets = new Insets(10, 15, 0, 15);
		gridBagConstraints4.gridx = 1;
		GridBagConstraints gridBagConstraints3 = new GridBagConstraints();
		gridBagConstraints3.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints3.gridy = 2;
		gridBagConstraints3.weightx = 1.0;
		gridBagConstraints3.insets = new Insets(15, 15, 0, 15);
		gridBagConstraints3.gridx = 1;
		GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
		gridBagConstraints2.gridx = 0;
		gridBagConstraints2.anchor = GridBagConstraints.EAST;
		gridBagConstraints2.insets = new Insets(10, 15, 0, 0);
		gridBagConstraints2.gridy = 3;
		jLabel2 = new JLabel();
		jLabel2.setText("MyProxy password:");
		GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
		gridBagConstraints1.gridx = 0;
		gridBagConstraints1.anchor = GridBagConstraints.EAST;
		gridBagConstraints1.insets = new Insets(15, 15, 0, 0);
		gridBagConstraints1.gridy = 2;
		jLabel1 = new JLabel();
		jLabel1.setText("MyProxy username:");
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		gridBagConstraints.gridx = 0;
		gridBagConstraints.insets = new Insets(15, 10, 0, 0);
		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.gridwidth = 2;
		gridBagConstraints.gridy = 0;
		jLabel = new JLabel();
		jLabel.setText("Upload a credential");
		this.setSize(376, 250);
		this.setLayout(new GridBagLayout());
		this.add(jLabel, gridBagConstraints);
		this.add(jLabel1, gridBagConstraints1);
		this.add(jLabel2, gridBagConstraints2);
		this.add(getUsernameTextField(), gridBagConstraints3);
		this.add(getPasswordField(), gridBagConstraints4);
		this.add(getInitButton(), gridBagConstraints11);
		this.add(jLabel4, gridBagConstraints21);
		this.add(getPrivateKeyPassphraseField(), gridBagConstraints31);
		if (lifetime_in_seconds <= 0) {
			this.add(jLabel3, gridBagConstraints5);
			this.add(getLifetimeComboBox(), gridBagConstraints6);
		}
	}

	/**
	 * This method initializes usernameTextField
	 * 
	 * @return javax.swing.JTextField
	 */
	private JTextField getUsernameTextField() {
		if (usernameTextField == null) {
			usernameTextField = new JTextField();
		}
		return usernameTextField;
	}

	/**
	 * This method initializes passwordField
	 * 
	 * @return javax.swing.JPasswordField
	 */
	private JPasswordField getPasswordField() {
		if (passwordField == null) {
			passwordField = new JPasswordField();
		}
		return passwordField;
	}

	/**
	 * This method initializes lifetimeComboBox
	 * 
	 * @return javax.swing.JComboBox
	 */
	private JComboBox getLifetimeComboBox() {
		if (lifetimeComboBox == null) {
			lifetimeComboBox = new JComboBox(defaultLifeTimes.split(","));
			lifetimeComboBox.setEditable(true);
		}
		return lifetimeComboBox;
	}

	/**
	 * This method initializes initButton
	 * 
	 * @return javax.swing.JButton
	 */
	private JButton getInitButton() {
		if (initButton == null) {
			initButton = new JButton();
			initButton.setText("Init");
			initButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent e) {

					MyProxyInitPanel.this.setCursor(Cursor
							.getPredefinedCursor(Cursor.WAIT_CURSOR));
					getInitButton().setEnabled(false);

					int seconds = -1;
					if (lifetime_in_seconds <= 0) {
						try {
							seconds = new Integer(
									(String) getLifetimeComboBox()
											.getSelectedItem()) * 3600 * 24;
						} catch (NumberFormatException e1) {
							MyProxyInitPanel.this
									.setCursor(Cursor
											.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
							getInitButton().setEnabled(true);
							Utils.showErrorMessage(MyProxyInitPanel.this,
									"notANumber", e1);
							return;
						}
					} else {
						seconds = lifetime_in_seconds;
					}
					GSSCredential baseProxy = null;
					// create credential from certificate
					try {
						baseProxy = PlainProxy.init(
								getPrivateKeyPassphraseField().getPassword(),
								seconds / 3600);
					} catch (Exception e1) {
						MyProxyInitPanel.this.setCursor(Cursor
								.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
						getInitButton().setEnabled(true);
						Utils.showErrorMessage(MyProxyInitPanel.this,
								"couldNotCreatePlainProxy", e1);
						return;
					}
					try {
						// prepare myproxy parameters
						InitParams params = MyProxy_light
								.prepareProxyParameters(
										getUsernameTextField().getText(),
										null,
										MyProxyInitPanel.this.allowed_renewers,
										MyProxyInitPanel.this.allowed_retrievers,
										null, seconds);
						// delegate proxy
						MyProxy_light.init(new MyProxy(
								MyProxyInitPanel.this.myproxyServer,
								MyProxyInitPanel.this.myproxyPort), baseProxy,
								params, getPasswordField().getPassword());
						listener.success(SUCCESS_ACTION_NAME, true, new Object[] {
								getUsernameTextField().getText(),
								getPasswordField().getPassword() });
					} catch (Exception e1) {
						MyProxyInitPanel.this.setCursor(Cursor
								.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
						getInitButton().setEnabled(true);
						Utils.showErrorMessage(MyProxyInitPanel.this,
								"couldNotUploadProxy", e1);
						return;
					}
					MyProxyInitPanel.this.setCursor(Cursor
							.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
					getInitButton().setEnabled(true);

				}
			});
		}
		return initButton;
	}

	/**
	 * This method initializes privateKeyPassphraseField
	 * 
	 * @return javax.swing.JPasswordField
	 */
	private JPasswordField getPrivateKeyPassphraseField() {
		if (privateKeyPassphraseField == null) {
			privateKeyPassphraseField = new JPasswordField();
		}
		return privateKeyPassphraseField;
	}

} // @jve:decl-index=0:visual-constraint="10,10"
