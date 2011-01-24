package grith.jgrith.view.swing;

import grith.jgrith.utils.ActionPerformedListener;
import grith.jgrith.utils.MyProxyLoginInformationHolder;

import java.awt.BorderLayout;

import javax.swing.JDialog;

public class MyProxyInitDialog extends JDialog implements
		ActionPerformedListener, MyProxyLoginInformationHolder {

	private MyProxyInitPanel myProxyInitPanel;

	private boolean success = false;
	private String username = null;
	private char[] password = null;

	private String myproxyServer = null;
	private int myproxyPort = -1;
	private int lifetime_in_seconds = -1;
	private String allowed_retrievers = null;
	private String allowed_renewers = null;

	/**
	 * Create the dialog
	 */
	public MyProxyInitDialog(String myproxyServer, int myproxyPort,
			int lifetime_in_seconds, String allowed_retrievers,
			String allowed_renewers) {
		super();
		this.setModal(true);
		this.myproxyServer = myproxyServer;
		this.myproxyPort = myproxyPort;
		this.lifetime_in_seconds = lifetime_in_seconds;
		this.allowed_renewers = allowed_renewers;
		this.allowed_retrievers = allowed_retrievers;
		setBounds(100, 100, 500, 375);
		getContentPane().add(getMyProxyInitPanel(), BorderLayout.CENTER);
		this.setVisible(true);
	}

	protected MyProxyInitPanel getMyProxyInitPanel() {
		if (myProxyInitPanel == null) {
			myProxyInitPanel = new MyProxyInitPanel(this, myproxyServer,
					myproxyPort, lifetime_in_seconds, allowed_retrievers,
					allowed_renewers);
		}
		return myProxyInitPanel;
	}

	public char[] getPassword() {
		return this.password;
	}

	public String getUsername() {
		return this.username;
	}

	public boolean proxyCreated() {
		return success;
	}

	public void success(String actionName, boolean success, Object[] params) {
		this.success = success;
		this.username = (String) params[0];
		this.password = (char[]) params[1];
		this.setVisible(false);

	}

	public boolean wasSuccess() {
		return success;
	}

}
