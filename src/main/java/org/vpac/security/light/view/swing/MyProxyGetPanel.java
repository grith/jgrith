package org.vpac.security.light.view.swing;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import org.globus.myproxy.MyProxyException;
import org.ietf.jgss.GSSCredential;
import org.vpac.security.light.myProxy.MyProxy_light;
import org.vpac.security.light.plainProxy.PlainProxy;
import org.vpac.security.light.utils.ActionPerformedListener;

public class MyProxyGetPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JLabel jLabel = null;
	private JTextField myProxyUsernameField = null;
	private JLabel jLabel1 = null;
	private JPasswordField myProxyPasswordField = null;
	private JButton getProxyButton = null;
	
	private String myproxyServer = null;
	private int myproxyPort = -1;
	private GSSCredential credential = null;
	private int lifetime_in_seconds = -1;
	
	ActionPerformedListener listener = null;
	
	public static final String SUCCESS_ACTION_NAME = "Proxy retrieved";  //  @jve:decl-index=0:
	public static final String CANCEL_ACTION_NAME = "User cancelled";
	private String defaultLifeTimes = "1,2,3,12,28,24,48,96";
	
	private GSSCredential myProxy = null;
	private JButton cancelButton = null;
	private JComboBox jComboBox = null;
	private JLabel jLabel2 = null;
	private JLabel jLabel3 = null;
	private JPasswordField keyPassphraseField = null;
	
	private boolean anonymousProxy = false;
	
	/**
	 * Creates a MyProxyGetPanel. 
	 * @param listener the listener that reacts when the proxy is retrieved (or the cancel button is pressed)
	 * @param myproxyServer the myproxy server
	 * @param myproxyPort the myproxy server port
	 * @param credential the credential to use to contact the myproxy server (use null if you want the panel to render a private key passphrase field)
	 * @param lifetime_in_seconds the lifetime in seconds. specify a number < 0 if you want the panel to render a combobox for the user to choose
	 */
	public MyProxyGetPanel(ActionPerformedListener listener, String myproxyServer,int  myproxyPort, GSSCredential credential, int lifetime_in_seconds) {
		super();
		this.listener = listener;
		this.myproxyServer = myproxyServer;
		this.myproxyPort = myproxyPort;
		this.credential = credential;
		this.lifetime_in_seconds = lifetime_in_seconds;
		initialize();
	}
	
	/**
	 * Creates a MyProxyGetPanel with a provided private key passphrase to use to create a (temporary) credential to contact the myproxy server.
	 * @param listener the listener that reacts when the proxy is retrieved (or the cancel button is pressed)
	 * @param myproxyServer the myproxy server
	 * @param myproxyPort the myproxy server port
	 * @param private_key_passphrase the passphrase of the user's private key. If null, the panel tries to retrieve an anonymous proxy.
	 * @param lifetime_in_seconds the credential to use to contact the myproxy server (use null if you want the panel to render a private key passphrase field)
	 * @throws Exception if the private key can't be unlocked with the provided passphrase
	 */
	public MyProxyGetPanel(ActionPerformedListener listener,String myproxyServer, int myproxyPort, int lifetime_in_seconds, char[] private_key_passphrase) throws Exception {
		super();
		this.listener = listener;
		this.myproxyServer = myproxyServer;
		this.myproxyPort = myproxyPort;
		this.lifetime_in_seconds = lifetime_in_seconds;
		if ( private_key_passphrase != null ) {
			this.credential = PlainProxy.init(private_key_passphrase, 1);
		} else {
			this.anonymousProxy = true;
		}
	}

	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
		GridBagConstraints gridBagConstraints5 = new GridBagConstraints();
		gridBagConstraints5.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints5.gridy = 0;
		gridBagConstraints5.weightx = 1.0;
		gridBagConstraints5.insets = new Insets(15, 15, 0, 15);
		gridBagConstraints5.gridx = 2;
		GridBagConstraints gridBagConstraints41 = new GridBagConstraints();
		gridBagConstraints41.gridx = 0;
		gridBagConstraints41.insets = new Insets(15, 10, 0, 0);
		gridBagConstraints41.anchor = GridBagConstraints.EAST;
		gridBagConstraints41.gridy = 0;
		jLabel3 = new JLabel();
		jLabel3.setText("Private key passphrase");
		GridBagConstraints gridBagConstraints31 = new GridBagConstraints();
		gridBagConstraints31.gridx = 0;
		gridBagConstraints31.anchor = GridBagConstraints.EAST;
		gridBagConstraints31.insets = new Insets(15, 0, 0, 0);
		gridBagConstraints31.gridy = 3;
		jLabel2 = new JLabel();
		jLabel2.setText("Lifetime (hours)");
		GridBagConstraints gridBagConstraints21 = new GridBagConstraints();
		gridBagConstraints21.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints21.gridy = 3;
		gridBagConstraints21.weightx = 1.0;
		gridBagConstraints21.insets = new Insets(15, 15, 0, 15);
		gridBagConstraints21.gridx = 2;
		GridBagConstraints gridBagConstraints11 = new GridBagConstraints();
		gridBagConstraints11.gridx = 0;
		gridBagConstraints11.anchor = GridBagConstraints.EAST;
		gridBagConstraints11.insets = new Insets(25, 0, 15, 0);
		gridBagConstraints11.gridy = 4;
		GridBagConstraints gridBagConstraints4 = new GridBagConstraints();
		gridBagConstraints4.gridx = 2;
		gridBagConstraints4.anchor = GridBagConstraints.EAST;
		gridBagConstraints4.insets = new Insets(25, 0, 15, 15);
		gridBagConstraints4.gridy = 4;
		GridBagConstraints gridBagConstraints3 = new GridBagConstraints();
		gridBagConstraints3.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints3.gridy = 2;
		gridBagConstraints3.weightx = 1.0;
		gridBagConstraints3.insets = new Insets(10, 15, 0, 15);
		gridBagConstraints3.gridwidth = 2;
		gridBagConstraints3.gridx = 1;
		GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
		gridBagConstraints2.gridx = 0;
		gridBagConstraints2.insets = new Insets(10, 10, 0, 0);
		gridBagConstraints2.anchor = GridBagConstraints.EAST;
		gridBagConstraints2.gridy = 2;
		jLabel1 = new JLabel();
		jLabel1.setText("MyProxy password:");
		GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
		gridBagConstraints1.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints1.gridy = 1;
		gridBagConstraints1.weightx = 1.0;
		gridBagConstraints1.insets = new Insets(15, 15, 0, 15);
		gridBagConstraints1.gridwidth = 2;
		gridBagConstraints1.gridx = 1;
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		gridBagConstraints.gridx = 0;
		gridBagConstraints.anchor = GridBagConstraints.EAST;
		gridBagConstraints.insets = new Insets(15, 10, 0, 0);
		gridBagConstraints.gridy = 1;
		jLabel = new JLabel();
		jLabel.setText("MyProxy username");
		this.setSize(357, 221);
		this.setLayout(new GridBagLayout());
		this.add(jLabel, gridBagConstraints);
		this.add(getMyProxyUsernameField(), gridBagConstraints1);
		this.add(jLabel1, gridBagConstraints2);
		this.add(getMyProxyPasswordField(), gridBagConstraints3);
		this.add(getGetProxyButton(), gridBagConstraints4);
		this.add(getCancelButton(), gridBagConstraints11);
		if ( lifetime_in_seconds < 0 ) {
			this.add(jLabel2, gridBagConstraints31);
			this.add(getJComboBox(), gridBagConstraints21);
		}
		if ( this.credential == null && ! anonymousProxy ) {
			this.add(jLabel3, gridBagConstraints41);
			this.add(getKeyPassphraseField(), gridBagConstraints5);
		}
	}

	/**
	 * This method initializes jTextField	
	 * 	
	 * @return javax.swing.JTextField	
	 */
	private JTextField getMyProxyUsernameField() {
		if (myProxyUsernameField == null) {
			myProxyUsernameField = new JTextField();
		}
		return myProxyUsernameField;
	}

	/**
	 * This method initializes jPasswordField	
	 * 	
	 * @return javax.swing.JPasswordField	
	 */
	private JPasswordField getMyProxyPasswordField() {
		if (myProxyPasswordField == null) {
			myProxyPasswordField = new JPasswordField();
		}
		return myProxyPasswordField;
	}

	/**
	 * This method initializes jButton	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getGetProxyButton() {
		if (getProxyButton == null) {
			getProxyButton = new JButton();
			getProxyButton.setText("Get MyProxy credential");
			getProxyButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent e) {
						try {
							int seconds = -1;
							if ( lifetime_in_seconds < 0 ) {
								try {
									seconds = new Integer((String)getJComboBox().getSelectedItem());
								} catch (NumberFormatException e1) {
									Utils.showErrorMessage(MyProxyGetPanel.this, "notANumber", e1);
									return;
								}
							} else {
								seconds = lifetime_in_seconds;
							}
							myProxy = MyProxy_light.getDelegation(myproxyServer, myproxyPort, credential, getMyProxyUsernameField().getText(), getMyProxyPasswordField().getPassword(), seconds);
							listener.success(SUCCESS_ACTION_NAME, true, new Object[]{myProxy});
						} catch (MyProxyException e1) {
							Utils.showErrorMessage(MyProxyGetPanel.this, "couldNotRetrieveProxy", e1);
							return;
						}
				}
			});
		}
		return getProxyButton;
	}
	
	public GSSCredential getMyProxy() {
		return myProxy;
	}

	/**
	 * This method initializes jButton1	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getCancelButton() {
		if (cancelButton == null) {
			cancelButton = new JButton();
			cancelButton.setText("Cancel");
		}
		return cancelButton;
	}

	/**
	 * This method initializes jComboBox	
	 * 	
	 * @return javax.swing.JComboBox	
	 */
	private JComboBox getJComboBox() {
		if (jComboBox == null) {
			jComboBox = new JComboBox(defaultLifeTimes.split(","));
		}
		return jComboBox;
	}

	/**
	 * This method initializes jPasswordField1	
	 * 	
	 * @return javax.swing.JPasswordField	
	 */
	private JPasswordField getKeyPassphraseField() {
		if (keyPassphraseField == null) {
			keyPassphraseField = new JPasswordField();
		}
		return keyPassphraseField;
	}

}  //  @jve:decl-index=0:visual-constraint="10,10"
